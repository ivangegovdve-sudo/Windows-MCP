"""Live, metadata-only filesystem index for Windows-MCP.

The index deliberately does not read file contents.  It stores a durable
SQLite metadata table and FTS5 path index on N:, while Windows directory
notifications provide the change stream used by the bounded reconciler.
Queries always return coverage and freshness instead of treating a baseline
as authoritative when a notification gap is known.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import sqlite3
import stat as stat_module
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

DEFAULT_INDEX_DB = Path(r"N:\WindowsMCP\filesystem-index\index.sqlite3")
DEFAULT_EXCLUSIONS = (".ssh", ".env*", "vault", ".vault", "vaults")
MAX_SEARCH_RESULTS = 100_000
MAX_LIST_RESULTS = 10_000
MAX_REFRESH_CHANGES = 2_000
WATCHER_BUFFER_BYTES = 64 * 1024

_WINDOWS_DRIVE_REMOTE = 4
_REPARSE_POINT = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


@dataclass(frozen=True)
class BuildStats:
    files: int = 0
    directories: int = 0
    boundaries: int = 0
    inaccessible: int = 0
    changes: int = 0
    duration_ms: float = 0.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp() -> str:
    return _now().isoformat(timespec="microseconds")


def _age_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return max(0.0, (_now() - timestamp).total_seconds())


def _display_path(path: str | os.PathLike[str]) -> str:
    return os.path.normpath(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _key(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(_display_path(path)).replace("/", "\\")


def _drive(path: str) -> str:
    drive, _ = os.path.splitdrive(path)
    return drive.upper()


def _is_under(path: str, parent: str, *, equal: bool = True) -> bool:
    path_key = _key(path)
    parent_key = _key(parent).rstrip("\\")
    if equal and path_key == parent_key:
        return True
    return path_key.startswith(parent_key + "\\")


def _drive_type(path: str) -> int | None:
    if os.name != "nt":
        return None
    drive = _drive(path)
    if not drive:
        return None
    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\"))
    except (AttributeError, OSError):
        return None


def _validate_local_path(path: str) -> str:
    if path.startswith(("\\\\", "//")):
        raise ValueError("UNC paths are not supported by the filesystem index")
    normalized = _display_path(path)
    if _drive_type(normalized) == _WINDOWS_DRIVE_REMOTE:
        raise ValueError("network-mapped paths are not supported by the filesystem index")
    return normalized


def _validate_db_path(path: str | os.PathLike[str]) -> str:
    if os.fspath(path) == ":memory:":
        return ":memory:"
    normalized = _validate_local_path(os.fspath(path))
    if _drive(normalized) != "N:":
        raise ValueError(
            f"filesystem index database must be stored on N:, got {normalized!r}"
        )
    return normalized


def _default_roots() -> list[str]:
    return [_display_path(Path.home()), _display_path(Path("D:/")), _display_path(Path("N:/"))]


def _is_reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _reparse_target(path: str) -> str:
    try:
        return os.readlink(path)
    except (OSError, ValueError):
        return "<reparse target unavailable>"


def _inaccessible_stat() -> os.stat_result:
    """Return metadata defaults for a path whose stat call was denied."""
    return os.stat_result((0,) * 10)


def _inaccessible_reason(exc: OSError) -> str:
    return f"inaccessible: {type(exc).__name__}: {exc}"


def _is_absolute_exclusion(value: str) -> bool:
    drive, _ = os.path.splitdrive(value)
    return bool(drive) or value.startswith(("\\\\", "/"))


class FilesystemIndex:
    """Durable metadata index with fail-closed freshness state."""

    def __init__(
        self,
        db_path: str | os.PathLike[str] = DEFAULT_INDEX_DB,
        roots: Iterable[str | os.PathLike[str]] | None = None,
        exclusions: Iterable[str] | None = None,
        *,
        mark_startup_stale: bool = True,
    ) -> None:
        self.db_path = _validate_db_path(db_path)
        self.roots = self._normalize_roots(roots)
        self.exclusions = list(exclusions or DEFAULT_EXCLUSIONS)
        self._db_directory = None if self.db_path == ":memory:" else _display_path(Path(self.db_path).parent)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._watchers: list[_DirectoryChangeWatcher] = []
        self._reconciler: threading.Thread | None = None
        self._started = False
        self._conn = self._connect()
        self._initialize_schema()
        if mark_startup_stale:
            self._mark_all_stale("service start has not yet established current coverage", full_gap=True)

    def _normalize_roots(
        self, roots: Iterable[str | os.PathLike[str]] | None
    ) -> list[str]:
        values = list(roots) if roots is not None else _default_roots()
        if not values:
            raise ValueError("at least one local index root is required")
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            path = _validate_local_path(os.fspath(value))
            key = _key(path)
            if key not in seen:
                normalized.append(path)
                seen.add(key)

        normalized.sort(key=lambda x: len(_key(x)))
        filtered: list[str] = []
        for root in normalized:
            is_sub_root = False
            for parent in filtered:
                if _is_under(root, parent):
                    is_sub_root = True
                    break
            if not is_sub_root:
                filtered.append(root)

        return filtered

    def _connect(self) -> sqlite3.Connection:
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        if self.db_path != ":memory:":
            journal_mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise RuntimeError(f"SQLite WAL could not be enabled (got {journal_mode!r})")
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _initialize_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS index_entries (
                    id INTEGER PRIMARY KEY,
                    root TEXT NOT NULL,
                    path TEXT NOT NULL,
                    normalized_path TEXT NOT NULL UNIQUE,
                    parent_path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    drive TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('file', 'folder', 'boundary')),
                    size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    mtime TEXT NOT NULL,
                    last_indexed_at TEXT NOT NULL,
                    boundary_reason TEXT,
                    reparse_target TEXT,
                    content_fingerprint TEXT,
                    content_fingerprint_kind TEXT
                );
                CREATE INDEX IF NOT EXISTS index_entries_root_parent
                    ON index_entries(root, parent_path, kind, normalized_path);
                CREATE INDEX IF NOT EXISTS index_entries_root_kind
                    ON index_entries(root, kind, normalized_path);
                CREATE VIRTUAL TABLE IF NOT EXISTS path_fts USING fts5(
                    normalized_path,
                    content='index_entries',
                    content_rowid='id',
                    tokenize='unicode61'
                );
                CREATE TABLE IF NOT EXISTS index_roots (
                    root TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK (state IN ('fresh', 'possibly_stale')),
                    reason TEXT NOT NULL,
                    row_count INTEGER NOT NULL DEFAULT 0,
                    event_seq INTEGER NOT NULL DEFAULT 0,
                    indexed_seq INTEGER NOT NULL DEFAULT 0,
                    last_indexed_at TEXT,
                    last_event_at TEXT,
                    last_reconciled_at TEXT,
                    requires_full_build INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS pending_changes (
                    root TEXT NOT NULL,
                    path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    event_seq INTEGER NOT NULL,
                    PRIMARY KEY (root, path),
                    FOREIGN KEY (root) REFERENCES index_roots(root) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS pending_changes_root_seq
                    ON pending_changes(root, event_seq);
                CREATE TRIGGER IF NOT EXISTS index_entries_ai AFTER INSERT ON index_entries
                BEGIN
                    INSERT INTO path_fts(rowid, normalized_path)
                    VALUES (new.id, new.normalized_path);
                END;
                CREATE TRIGGER IF NOT EXISTS index_entries_ad AFTER DELETE ON index_entries
                BEGIN
                    INSERT INTO path_fts(path_fts, rowid, normalized_path)
                    VALUES ('delete', old.id, old.normalized_path);
                END;
                CREATE TRIGGER IF NOT EXISTS index_entries_au AFTER UPDATE OF normalized_path ON index_entries
                BEGIN
                    INSERT INTO path_fts(path_fts, rowid, normalized_path)
                    VALUES ('delete', old.id, old.normalized_path);
                    INSERT INTO path_fts(rowid, normalized_path)
                    VALUES (new.id, new.normalized_path);
                END;
                """
            )
            for root in self.roots:
                self._conn.execute(
                    """
                    INSERT INTO index_roots(root, state, reason)
                    VALUES (?, 'possibly_stale', 'service has not established current coverage')
                    ON CONFLICT(root) DO NOTHING
                    """,
                    (root,),
                )
            self._conn.commit()

    def close(self) -> None:
        self.stop()
        with self._lock:
            self._conn.commit()
            self._conn.close()

    def _root_for(self, path: str) -> str:
        for root in self.roots:
            if _is_under(path, root):
                return root
        raise ValueError(f"path is outside configured index roots: {path}")

    def _is_index_path(self, path: str) -> bool:
        return self._db_directory is not None and _is_under(path, self._db_directory)

    def _exclusion_reason(self, path: str, root: str) -> str | None:
        if self._is_index_path(path):
            return "index database directory"
        for configured in self.exclusions:
            if _is_absolute_exclusion(configured):
                try:
                    if _is_under(path, _validate_local_path(configured)):
                        return f"configured exclusion: {configured}"
                except ValueError:
                    continue
                continue
            for part in Path(path).parts:
                if fnmatch.fnmatchcase(part.casefold(), configured.casefold()):
                    return f"configured exclusion: {configured}"
        return None

    def _row(
        self,
        path: str,
        root: str,
        st: os.stat_result,
        kind: str,
        indexed_at: str,
        *,
        boundary_reason: str | None = None,
        reparse_target: str | None = None,
    ) -> dict[str, object]:
        path = _display_path(path)
        size = getattr(st, "st_size", 0) or 0
        mtime_ns = getattr(st, "st_mtime_ns", 0) or 0
        mtime = getattr(st, "st_mtime", 0) or 0
        return {
            "root": root,
            "path": path,
            "normalized_path": _key(path),
            "parent_path": _key(Path(path).parent) if _key(path) != _key(root) else "",
            "name": Path(path).name or path,
            "drive": _drive(path),
            "kind": kind,
            "size": int(size),
            "mtime_ns": int(mtime_ns),
            "mtime": datetime.fromtimestamp(mtime, timezone.utc).isoformat(),
            "last_indexed_at": indexed_at,
            "boundary_reason": boundary_reason,
            "reparse_target": reparse_target,
            # Layer two owns this field. Layer one never opens content.
            "content_fingerprint": None,
            "content_fingerprint_kind": None,
        }

    def _scan_tree(
        self, root: str, *, coverage_root: str | None = None
    ) -> Iterable[dict[str, object]]:
        coverage_root = coverage_root or root
        indexed_at = _timestamp()
        if self._is_index_path(root):
            return
        try:
            root_stat = os.stat(root, follow_symlinks=False)
        except OSError as exc:
            yield self._row(
                root,
                coverage_root,
                _inaccessible_stat(),
                "boundary",
                indexed_at,
                boundary_reason=_inaccessible_reason(exc),
            )
            return
        if _is_reparse(root_stat):
            yield self._row(
                root,
                coverage_root,
                root_stat,
                "boundary",
                indexed_at,
                boundary_reason="root is a reparse point",
                reparse_target=_reparse_target(root),
            )
            return
        exclusion_reason = self._exclusion_reason(root, coverage_root)
        if exclusion_reason:
            yield self._row(
                root,
                coverage_root,
                root_stat,
                "boundary",
                indexed_at,
                boundary_reason=exclusion_reason,
            )
            return
        stack = [(root, root_stat)]
        seen_directories: dict[tuple[int, int], str] = {}
        root_identity = (int(root_stat.st_dev), int(root_stat.st_ino))
        seen_directories[root_identity] = root
        while stack:
            current, current_stat = stack.pop()
            try:
                entries = sorted(os.scandir(current), key=lambda item: item.name.casefold())
            except OSError as exc:
                yield self._row(
                    current,
                    coverage_root,
                    current_stat,
                    "boundary",
                    indexed_at,
                    boundary_reason=_inaccessible_reason(exc),
                )
                continue
            yield self._row(current, coverage_root, current_stat, "folder", indexed_at)
            for entry in entries:
                path = _display_path(entry.path)
                if self._is_index_path(path):
                    continue
                try:
                    st = os.stat(path, follow_symlinks=False)
                except OSError as exc:
                    yield self._row(
                        path,
                        coverage_root,
                        _inaccessible_stat(),
                        "boundary",
                        indexed_at,
                        boundary_reason=_inaccessible_reason(exc),
                    )
                    continue

                exclusion_reason = self._exclusion_reason(path, coverage_root)
                if exclusion_reason:
                    yield self._row(
                        path,
                        coverage_root,
                        st,
                        "boundary",
                        indexed_at,
                        boundary_reason=exclusion_reason,
                    )
                    continue

                if _is_reparse(st):
                    yield self._row(
                        path,
                        coverage_root,
                        st,
                        "boundary",
                        indexed_at,
                        boundary_reason="reparse point; not traversed",
                        reparse_target=_reparse_target(path),
                    )
                    continue

                if stat_module.S_ISDIR(st.st_mode):
                    identity = (int(st.st_dev), int(st.st_ino))
                    if identity in seen_directories:
                        yield self._row(
                            path,
                            coverage_root,
                            st,
                            "boundary",
                            indexed_at,
                            boundary_reason="directory identity already indexed; not traversed",
                            reparse_target=seen_directories[identity],
                        )
                        continue
                    seen_directories[identity] = path
                    stack.append((path, st))
                    continue

                if stat_module.S_ISREG(st.st_mode):
                    yield self._row(path, coverage_root, st, "file", indexed_at)
                else:
                    yield self._row(
                        path,
                        coverage_root,
                        st,
                        "boundary",
                        indexed_at,
                        boundary_reason="special filesystem entry; not traversed",
                    )

    def _mark_all_stale(self, reason: str, *, full_gap: bool) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE index_roots
                SET state='possibly_stale', reason=?, requires_full_build=CASE WHEN ? THEN 1 ELSE requires_full_build END
                """,
                (reason, int(full_gap)),
            )
            self._conn.commit()

    def _mark_root_stale(self, root: str, reason: str, *, full_gap: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE index_roots
                SET state='possibly_stale', reason=?, requires_full_build=CASE WHEN ? THEN 1 ELSE requires_full_build END
                WHERE root=?
                """,
                (reason, int(full_gap), root),
            )
            self._conn.commit()

    def build(self) -> BuildStats:
        """Perform an operator-controlled full baseline build."""
        started = time.perf_counter()
        totals = {"files": 0, "directories": 0, "boundaries": 0, "inaccessible": 0}
        self._mark_all_stale("operator build in progress", full_gap=True)
        for root in self.roots:
            with self._lock:
                state = self._conn.execute(
                    "SELECT event_seq FROM index_roots WHERE root=?", (root,)
                ).fetchone()
                start_event_seq = int(state[0])
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    self._conn.execute("DELETE FROM index_entries WHERE root=?", (root,))
                    root_counts = {
                        "files": 0,
                        "directories": 0,
                        "boundaries": 0,
                        "inaccessible": 0,
                    }
                    for row in self._scan_tree(root):
                        self._conn.execute(
                            """
                            INSERT INTO index_entries(
                                root, path, normalized_path, parent_path, name, drive, kind,
                                size, mtime_ns, mtime, last_indexed_at, boundary_reason,
                                reparse_target, content_fingerprint, content_fingerprint_kind
                            ) VALUES(
                                :root, :path, :normalized_path, :parent_path, :name, :drive, :kind,
                                :size, :mtime_ns, :mtime, :last_indexed_at, :boundary_reason,
                                :reparse_target, :content_fingerprint, :content_fingerprint_kind
                            )
                            ON CONFLICT(normalized_path) DO UPDATE SET
                                root=excluded.root, path=excluded.path, parent_path=excluded.parent_path,
                                name=excluded.name, drive=excluded.drive, kind=excluded.kind,
                                size=excluded.size, mtime_ns=excluded.mtime_ns, mtime=excluded.mtime,
                                last_indexed_at=excluded.last_indexed_at,
                                boundary_reason=excluded.boundary_reason,
                                reparse_target=excluded.reparse_target,
                                content_fingerprint=excluded.content_fingerprint,
                                content_fingerprint_kind=excluded.content_fingerprint_kind
                            """,
                            row,
                        )
                        kind = str(row["kind"])
                        if kind == "file":
                            root_counts["files"] += 1
                        elif kind == "folder":
                            root_counts["directories"] += 1
                        else:
                            root_counts["boundaries"] += 1
                            if str(row["boundary_reason"] or "").startswith("inaccessible:"):
                                root_counts["inaccessible"] += 1
                    indexed_row_count = sum(
                        root_counts[key] for key in ("files", "directories", "boundaries")
                    )
                    current = self._conn.execute(
                        "SELECT event_seq FROM index_roots WHERE root=?", (root,)
                    ).fetchone()
                    current_seq = int(current[0])
                    last_indexed = _timestamp()
                    if current_seq == start_event_seq:
                        self._conn.execute("DELETE FROM pending_changes WHERE root=?", (root,))
                        self._conn.execute(
                            """
                            UPDATE index_roots
                            SET state='fresh', reason='', row_count=?, indexed_seq=?,
                                last_indexed_at=?, last_reconciled_at=?, requires_full_build=0
                            WHERE root=?
                            """,
                            (
                                indexed_row_count,
                                current_seq,
                                last_indexed,
                                last_indexed,
                                root,
                            ),
                        )
                    else:
                        self._conn.execute(
                            """
                            UPDATE index_roots
                            SET state='possibly_stale',
                                reason='notification observed during operator build',
                                row_count=?, requires_full_build=0
                            WHERE root=?
                            """,
                            (indexed_row_count, root),
                        )
                    self._conn.commit()
                    for key in totals:
                        totals[key] += root_counts[key]
                except Exception as exc:
                    self._conn.rollback()
                    self._mark_root_stale(root, f"operator build failed: {exc}", full_gap=True)
                    raise
        return BuildStats(**totals, duration_ms=(time.perf_counter() - started) * 1000)

    def _status_rows(self, scope: str | None = None) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT roots.*,
                       (SELECT COUNT(*) FROM index_entries AS entries
                        WHERE entries.root = roots.root) AS actual_row_count,
                       (SELECT COUNT(*) FROM index_entries AS inaccessible
                        WHERE inaccessible.root = roots.root
                          AND inaccessible.boundary_reason LIKE 'inaccessible:%')
                        AS inaccessible_count
                FROM index_roots AS roots
                ORDER BY roots.root
                """
            ).fetchall()
            reason_rows = self._conn.execute(
                """
                SELECT root, boundary_reason, COUNT(*) AS count
                FROM index_entries
                WHERE kind='boundary' AND boundary_reason LIKE 'inaccessible:%'
                GROUP BY root, boundary_reason
                ORDER BY root, boundary_reason
                """
            ).fetchall()
        reasons_by_root: dict[str, dict[str, int]] = {}
        for reason_row in reason_rows:
            reason = str(reason_row["boundary_reason"] or "")
            if reason.startswith("inaccessible: "):
                reason = reason[len("inaccessible: "):]
            reasons_by_root.setdefault(str(reason_row["root"]), {})[reason] = int(
                reason_row["count"]
            )
        if scope is not None:
            rows = [row for row in rows if _is_under(scope, row["root"]) or _is_under(row["root"], scope)]
        return [
            {
                "root": row["root"],
                "state": row["state"],
                "reason": row["reason"],
                "row_count": int(row["actual_row_count"]),
                "event_seq": int(row["event_seq"]),
                "indexed_seq": int(row["indexed_seq"]),
                "last_indexed_at": row["last_indexed_at"],
                "last_event_at": row["last_event_at"],
                "last_reconciled_at": row["last_reconciled_at"],
                "requires_full_build": bool(row["requires_full_build"]),
                "inaccessible_count": int(row["inaccessible_count"]),
                "inaccessible_reasons": reasons_by_root.get(row["root"], {}),
            }
            for row in rows
        ]

    def _response_base(self, scope: str | None = None) -> dict[str, object]:
        coverage = self._status_rows(scope)
        latest = [row["last_indexed_at"] for row in coverage if row["last_indexed_at"]]
        ages = [_age_seconds(value) for value in latest]
        pending = self._pending_count()
        return {
            "freshness": "fresh" if coverage and all(row["state"] == "fresh" for row in coverage) else "possibly_stale",
            "index_age_seconds": max(ages) if ages else None,
            "coverage": coverage,
            "searched_roots": [row["root"] for row in coverage],
            "exclusions": list(self.exclusions) + ([self._db_directory] if self._db_directory else []),
            "pending_changes": pending,
        }

    def _pending_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM pending_changes").fetchone()[0])

    def status(self) -> dict[str, object]:
        result = self._response_base()
        result.update(
            {
                "database": self.db_path,
                "journal_mode": str(self._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                "fts5": True,
                "fingerprint": {
                    "field": "content_fingerprint",
                    "kind_field": "content_fingerprint_kind",
                    "state": "reserved; layer one never reads content",
                },
            }
        )
        return result

    def _fts_query(self, pattern: str) -> str | None:
        safe_terms = []
        casefolded_pattern = pattern.casefold()
        for match in _TOKEN_RE.finditer(casefolded_pattern):
            start = match.start()
            if start == 0 or casefolded_pattern[start - 1] not in '*?[]':
                safe_terms.append(match.group())
        if not safe_terms:
            return None
        # Prefix terms let '*.md' use the FTS5 path index while the final
        # fnmatch below preserves the caller's actual glob semantics.
        return " AND ".join(f'"{token.replace(chr(34), chr(34) * 2)}"*' for token in safe_terms[:8])

    @staticmethod
    def _matches_pattern(path: str, pattern: str) -> bool:
        normalized_pattern = pattern.replace("/", "\\").casefold()
        path_key = _key(path)
        if "\\" in normalized_pattern or ":" in normalized_pattern:
            return fnmatch.fnmatchcase(path_key, normalized_pattern) or fnmatch.fnmatchcase(
                Path(path).name.casefold(), normalized_pattern
            )
        return fnmatch.fnmatchcase(Path(path).name.casefold(), normalized_pattern)

    @staticmethod
    def _safe_sql_glob(pattern: str) -> tuple[str, str] | None:
        """Return a SQLite GLOB predicate when it preserves the glob contract."""
        normalized_pattern = pattern.replace("/", "\\").casefold()
        # SQLite and fnmatch differ in character-class edge cases. Keep those
        # patterns on the exact Python matcher rather than widening results.
        if "[" in normalized_pattern or "]" in normalized_pattern:
            return None
        if "\\" in normalized_pattern or ":" in normalized_pattern:
            return "lower(e.normalized_path) GLOB lower(?)", normalized_pattern
        return "lower(e.name) GLOB lower(?)", normalized_pattern

    def search(
        self,
        pattern: str,
        *,
        scope: str | None = None,
        kind: str = "file",
        limit: int = MAX_SEARCH_RESULTS,
    ) -> dict[str, object]:
        pattern = pattern.strip()
        if not pattern:
            raise ValueError("pattern is required")
        if kind not in {"file", "folder", "boundary", "all"}:
            raise ValueError("kind must be one of file, folder, boundary, all")
        limit = max(1, min(int(limit), MAX_SEARCH_RESULTS))
        normalized_scope = _validate_local_path(scope) if scope else None
        if normalized_scope:
            self._root_for(normalized_scope)
        started = time.perf_counter()
        fts_query = self._fts_query(pattern)
        sql_glob = self._safe_sql_glob(pattern)
        where = ["1=1"]
        params: list[object] = []
        if fts_query:
            from_sql = "index_entries AS e JOIN path_fts AS f ON f.rowid = e.id"
            where.append("f.path_fts MATCH ?")
            params.append(fts_query)
        else:
            from_sql = "index_entries AS e"
        if kind != "all":
            where.append("e.kind = ?")
            params.append(kind)
        if normalized_scope:
            scope_key = _key(normalized_scope)
            where.append("(e.normalized_path = ? OR e.normalized_path LIKE ? ESCAPE '\\')")
            params.extend([scope_key, scope_key + "\\%"])
        if sql_glob:
            where.append(sql_glob[0])
            params.append(sql_glob[1])
        query = (
            "SELECT e.* FROM "
            + from_sql
            + " WHERE "
            + " AND ".join(where)
            + " ORDER BY e.normalized_path"
        )
        items: list[dict[str, object]] = []
        if sql_glob:
            aggregate_query = (
                "SELECT COUNT(*), COALESCE(SUM(e.size), 0) FROM "
                + from_sql
                + " WHERE "
                + " AND ".join(where)
            )
            with self._lock:
                aggregate = self._conn.execute(aggregate_query, params).fetchone()
                rows = self._conn.execute(query + " LIMIT ?", [*params, limit]).fetchall()
            total = int(aggregate[0])
            total_size = int(aggregate[1])
            items = [self._public_row(row) for row in rows]
        else:
            total = 0
            total_size = 0
            with self._lock:
                rows = self._conn.execute(query, params).fetchall()
            for row in rows:
                if not self._matches_pattern(row["path"], pattern):
                    continue
                total += 1
                total_size += int(row["size"])
                if len(items) < limit:
                    items.append(self._public_row(row))
        result = self._response_base(normalized_scope)
        result.update(
            {
                "pattern": pattern,
                "kind": kind,
                "items": items,
                "total_matches": total,
                "total_size": total_size,
                "truncated": total > limit,
                "query_ms": (time.perf_counter() - started) * 1000,
            }
        )
        return result

    def list_directory(
        self, path: str, *, limit: int = MAX_LIST_RESULTS
    ) -> dict[str, object]:
        normalized_path = _validate_local_path(path)
        self._root_for(normalized_path)
        limit = max(1, min(int(limit), MAX_LIST_RESULTS))
        parent_key = _key(normalized_path)
        started = time.perf_counter()
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM index_entries
                WHERE parent_path = ?
                ORDER BY CASE kind WHEN 'folder' THEN 0 WHEN 'boundary' THEN 1 ELSE 2 END,
                         normalized_path
                """,
                (parent_key,),
            ).fetchall()
        items = [self._public_row(row) for row in rows[:limit]]
        result = self._response_base(normalized_path)
        result.update(
            {
                "path": normalized_path,
                "items": items,
                "total_entries": len(rows),
                "truncated": len(rows) > limit,
                "query_ms": (time.perf_counter() - started) * 1000,
            }
        )
        return result

    def get_metadata(self, path: str) -> dict[str, object]:
        requested_path = _validate_local_path(path)
        root = self._root_for(requested_path)
        requested_key = _key(requested_path)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM index_entries WHERE normalized_path=?", (requested_key,)
            ).fetchone()
            if row is None:
                row = self._conn.execute(
                    """
                    SELECT * FROM index_entries
                    WHERE root=? AND kind='boundary'
                      AND (? = normalized_path OR ? LIKE normalized_path || '\\%')
                    ORDER BY length(normalized_path) DESC
                    LIMIT 1
                    """,
                    (root, requested_key, requested_key),
                ).fetchone()
        if row is None:
            entry = None
            boundary = None
            stat_path = requested_path
        else:
            entry = self._public_row(row)
            boundary = entry if entry["kind"] == "boundary" and entry["path"] != requested_path else None
            stat_path = str(entry["path"])

        live: dict[str, object] = {"exists": False, "path": stat_path}
        try:
            live_stat = os.stat(stat_path, follow_symlinks=False)
        except OSError as exc:
            live["error"] = str(exc)
        else:
            live.update(
                {
                    "exists": True,
                    "size": int(live_stat.st_size),
                    "mtime_ns": int(live_stat.st_mtime_ns),
                    "mtime": datetime.fromtimestamp(live_stat.st_mtime, timezone.utc).isoformat(),
                    "kind": "folder" if stat_module.S_ISDIR(live_stat.st_mode) else "file",
                }
            )
        result = self._response_base(requested_path)
        if entry and not live.get("exists"):
            result["freshness"] = "possibly_stale"
        elif entry and boundary is None and live.get("exists"):
            if live.get("mtime_ns") != entry.get("mtime_ns") or live.get("size") != entry.get("size"):
                result["freshness"] = "possibly_stale"
        elif entry is None and live.get("exists"):
            # A live path missing from a supposedly fresh index is positive
            # evidence that its completeness denominator is no longer safe.
            result["freshness"] = "possibly_stale"
        result.update(
            {
                "requested_path": requested_path,
                "entry": entry,
                "boundary": boundary,
                "live": live,
                "fingerprint": None,
            }
        )
        return result

    def record_change(self, path: str, *, action: str = "modified") -> None:
        """Persist one notification and fail closed before reconciliation."""
        normalized_path = _validate_local_path(path)
        if self._is_index_path(normalized_path):
            return
        root = self._root_for(normalized_path)
        observed_at = _timestamp()
        with self._lock:
            row = self._conn.execute(
                "SELECT event_seq FROM index_roots WHERE root=?", (root,)
            ).fetchone()
            event_seq = int(row[0]) + 1
            self._conn.execute(
                """
                UPDATE index_roots
                SET state='possibly_stale', reason='filesystem change observed; reconciliation pending',
                    event_seq=?, last_event_at=?
                WHERE root=?
                """,
                (event_seq, observed_at, root),
            )
            self._conn.execute(
                """
                INSERT INTO pending_changes(root, path, action, observed_at, event_seq)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(root, path) DO UPDATE SET
                    action=excluded.action, observed_at=excluded.observed_at,
                    event_seq=excluded.event_seq
                """,
                (root, normalized_path, action, observed_at, event_seq),
            )
            self._conn.commit()
        self._wake.set()

    def mark_root_possibly_stale(self, root: str, reason: str) -> None:
        normalized_root = _validate_local_path(root)
        configured_root = self._root_for(normalized_root)
        self._mark_root_stale(configured_root, reason, full_gap=True)

    def _public_row(self, row: sqlite3.Row) -> dict[str, object]:
        return {
            "root": row["root"],
            "path": row["path"],
            "name": row["name"],
            "drive": row["drive"],
            "kind": row["kind"],
            "size": int(row["size"]),
            "mtime_ns": int(row["mtime_ns"]),
            "mtime": row["mtime"],
            "parent_path": row["parent_path"],
            "last_indexed_at": row["last_indexed_at"],
            "boundary_reason": row["boundary_reason"],
            "reparse_target": row["reparse_target"],
            "content_fingerprint": row["content_fingerprint"],
            "content_fingerprint_kind": row["content_fingerprint_kind"],
        }

    def _reconcile_one(self, root: str, path: str, action: str) -> None:
        if self._is_index_path(path):
            return
        if action in {"removed", "renamed_old"} and not os.path.lexists(path):
            with self._lock:
                self._conn.execute(
                    "DELETE FROM index_entries WHERE root=? AND (normalized_path=? OR normalized_path LIKE ? ESCAPE '\\')",
                    (root, _key(path), _key(path) + "\\%"),
                )
                self._conn.commit()
            return

        target = path if os.path.isdir(path) else _display_path(Path(path).parent)
        rows = list(self._scan_directory(target, root))
        target_key = _key(target)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if os.path.isdir(path) and action in {"created", "renamed_new"}:
                    self._conn.execute(
                        "DELETE FROM index_entries WHERE root=? AND (normalized_path=? OR normalized_path LIKE ? ESCAPE '\\')",
                        (root, _key(path), _key(path) + "\\%"),
                    )
                    rows = list(self._scan_tree(path, coverage_root=root))
                else:
                    self._conn.execute(
                        "DELETE FROM index_entries WHERE root=? AND parent_path=?",
                        (root, target_key),
                    )
                for row in rows:
                    self._conn.execute(
                        """
                        INSERT INTO index_entries(
                            root, path, normalized_path, parent_path, name, drive, kind,
                            size, mtime_ns, mtime, last_indexed_at, boundary_reason,
                            reparse_target, content_fingerprint, content_fingerprint_kind
                        ) VALUES(
                            :root, :path, :normalized_path, :parent_path, :name, :drive, :kind,
                            :size, :mtime_ns, :mtime, :last_indexed_at, :boundary_reason,
                            :reparse_target, :content_fingerprint, :content_fingerprint_kind
                        )
                        ON CONFLICT(normalized_path) DO UPDATE SET
                            root=excluded.root, path=excluded.path, parent_path=excluded.parent_path,
                            name=excluded.name, drive=excluded.drive, kind=excluded.kind,
                            size=excluded.size, mtime_ns=excluded.mtime_ns, mtime=excluded.mtime,
                            last_indexed_at=excluded.last_indexed_at,
                            boundary_reason=excluded.boundary_reason,
                            reparse_target=excluded.reparse_target,
                            content_fingerprint=excluded.content_fingerprint,
                            content_fingerprint_kind=excluded.content_fingerprint_kind
                        """,
                        row,
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _scan_directory(self, path: str, root: str) -> Iterable[dict[str, object]]:
        if self._is_index_path(path) or self._exclusion_reason(path, root):
            return []
        try:
            directory_stat = os.stat(path, follow_symlinks=False)
        except OSError:
            return []
        if not stat_module.S_ISDIR(directory_stat.st_mode) or _is_reparse(directory_stat):
            return []
        try:
            entries = sorted(os.scandir(path), key=lambda item: item.name.casefold())
        except OSError as exc:
            if not os.path.exists(path):
                return []
            raise OSError(f"cannot enumerate {path}: {exc}") from exc
        indexed_at = _timestamp()
        rows: list[dict[str, object]] = []
        for entry in entries:
            entry_path = _display_path(entry.path)
            if self._is_index_path(entry_path):
                continue
            try:
                st = os.stat(entry_path, follow_symlinks=False)
            except OSError:
                continue
            exclusion_reason = self._exclusion_reason(entry_path, root)
            if exclusion_reason:
                rows.append(self._row(entry_path, root, st, "boundary", indexed_at, boundary_reason=exclusion_reason))
            elif _is_reparse(st):
                rows.append(
                    self._row(
                        entry_path,
                        root,
                        st,
                        "boundary",
                        indexed_at,
                        boundary_reason="reparse point; not traversed",
                        reparse_target=_reparse_target(entry_path),
                    )
                )
            elif stat_module.S_ISDIR(st.st_mode):
                rows.append(self._row(entry_path, root, st, "folder", indexed_at))
            elif stat_module.S_ISREG(st.st_mode):
                rows.append(self._row(entry_path, root, st, "file", indexed_at))
            else:
                rows.append(
                    self._row(
                        entry_path,
                        root,
                        st,
                        "boundary",
                        indexed_at,
                        boundary_reason="special filesystem entry; not traversed",
                    )
                )
        return rows

    def refresh(self, *, full: bool = False) -> BuildStats:
        """Reconcile durable notifications, or fully verify when requested."""
        if full:
            pending_count = self._pending_count()
            stats = self.build()
            return BuildStats(
                files=stats.files,
                directories=stats.directories,
                boundaries=stats.boundaries,
                inaccessible=stats.inaccessible,
                changes=pending_count,
                duration_ms=stats.duration_ms,
            )
        started = time.perf_counter()
        with self._lock:
            pending = self._conn.execute(
                "SELECT root, path, action, event_seq FROM pending_changes ORDER BY event_seq LIMIT ?",
                (MAX_REFRESH_CHANGES,),
            ).fetchall()
        counts = {"files": 0, "directories": 0, "boundaries": 0, "changes": 0}
        for change in pending:
            root, path, action = change["root"], change["path"], change["action"]
            try:
                self._reconcile_one(root, path, action)
            except Exception as exc:
                self._mark_root_stale(root, f"bounded reconciliation failed: {exc}", full_gap=True)
                raise
            with self._lock:
                self._conn.execute(
                    "DELETE FROM pending_changes WHERE root=? AND path=? AND event_seq=?",
                    (root, path, change["event_seq"]),
                )
                remaining = self._conn.execute(
                    "SELECT COUNT(*) FROM pending_changes WHERE root=?", (root,)
                ).fetchone()[0]
                row_count = self._conn.execute(
                    "SELECT COUNT(*) FROM index_entries WHERE root=?", (root,)
                ).fetchone()[0]
                root_state = self._conn.execute(
                    "SELECT event_seq, requires_full_build FROM index_roots WHERE root=?", (root,)
                ).fetchone()
                if not remaining and not root_state["requires_full_build"]:
                    now = _timestamp()
                    self._conn.execute(
                        """
                        UPDATE index_roots
                        SET state='fresh', reason='', row_count=?, indexed_seq=?, last_reconciled_at=?
                        WHERE root=? AND event_seq=?
                        """,
                        (row_count, root_state["event_seq"], now, root, root_state["event_seq"]),
                    )
                else:
                    self._conn.execute(
                        "UPDATE index_roots SET row_count=? WHERE root=?",
                        (row_count, root),
                    )
                self._conn.commit()
            counts["changes"] += 1
        if pending and len(pending) >= MAX_REFRESH_CHANGES:
            self._mark_all_stale("bounded refresh limit reached", full_gap=True)
        return BuildStats(**counts, duration_ms=(time.perf_counter() - started) * 1000)

    def start(self, *, watchers: bool = True) -> None:
        if self._started:
            return
        self._started = True
        self._stop.clear()
        self._mark_all_stale("service start; notification coverage is not yet established", full_gap=True)
        if watchers:
            for root in self.roots:
                watcher = _DirectoryChangeWatcher(root, self)
                try:
                    watcher.start()
                except Exception as exc:
                    self._mark_root_stale(root, f"watcher could not attach: {exc}", full_gap=True)
                    continue
                self._watchers.append(watcher)
            self._reconciler = threading.Thread(
                target=self._reconcile_loop,
                name="windows-mcp-index-reconciler",
                daemon=True,
            )
            self._reconciler.start()

    def stop(self) -> None:
        if not self._started:
            return
        self._stop.set()
        self._wake.set()
        for watcher in self._watchers:
            watcher.stop()
        for watcher in self._watchers:
            watcher.join(timeout=2)
        if self._reconciler:
            self._reconciler.join(timeout=2)
        self._watchers.clear()
        self._reconciler = None
        self._started = False

    def _reconcile_loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=0.25)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self.refresh()
            except Exception:
                logger.exception("live filesystem index reconciliation failed")


class _DirectoryChangeWatcher(threading.Thread):
    def __init__(self, root: str, index: FilesystemIndex) -> None:
        super().__init__(name=f"windows-mcp-index-watcher-{_drive(root) or 'root'}", daemon=True)
        self.root = root
        self.index = index
        self._stop_event = threading.Event()
        self._handle = None

    def stop(self) -> None:
        self._stop_event.set()
        if self._handle is not None:
            try:
                import win32file

                win32file.CloseHandle(self._handle)
            except Exception:
                pass

    def run(self) -> None:
        try:
            import win32con
            import win32file

            self._handle = win32file.CreateFile(
                self.root,
                win32con.FILE_LIST_DIRECTORY,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            while not self._stop_event.is_set():
                changes = win32file.ReadDirectoryChangesW(
                    self._handle,
                    WATCHER_BUFFER_BYTES,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME
                    | win32con.FILE_NOTIFY_CHANGE_DIR_NAME
                    | win32con.FILE_NOTIFY_CHANGE_SIZE
                    | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
                    | win32con.FILE_NOTIFY_CHANGE_CREATION,
                )
                if not changes:
                    self.index.mark_root_possibly_stale(
                        self.root, "watcher returned an unobserved gap"
                    )
                    continue
                for action, relative_name in changes:
                    action_name = {
                        1: "created",
                        2: "removed",
                        3: "modified",
                        4: "renamed_old",
                        5: "renamed_new",
                    }.get(int(action), "modified")
                    self.index.record_change(
                        _display_path(Path(self.root) / relative_name), action=action_name
                    )
        except Exception as exc:
            if not self._stop_event.is_set():
                self.index.mark_root_possibly_stale(self.root, f"watcher gap: {exc}")
        finally:
            if self._handle is not None:
                try:
                    import win32file

                    win32file.CloseHandle(self._handle)
                except Exception:
                    pass
                self._handle = None
