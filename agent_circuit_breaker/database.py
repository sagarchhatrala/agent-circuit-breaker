"""Owner-registered SQLite maintenance with preview and transactional limits.

Preview executes on a private in-memory backup. Actual execution obtains a write
lock, revalidates the approved table/schema snapshot, then checks the measured row
count and resulting snapshot before commit. No arbitrary agent SQL is accepted.
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

from agent_circuit_breaker.workflow import MAX_BYTES, canonical, digest
from agent_circuit_breaker.runtime import ExecutionUncertain


class SQLiteMaintenance:
    def __init__(self, configuration: dict):
        if not isinstance(configuration, dict) or set(configuration) != {"path", "operations"}:
            raise ValueError("database requires path and registered operations")
        raw = Path(configuration["path"])
        if not raw.is_absolute() or raw.is_symlink() or any(p.is_symlink() for p in raw.parents):
            raise ValueError("database must be an absolute owner-controlled path without symlinks")
        self.path = raw.resolve(strict=True)
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("database must be a regular single-link file")
        self.identity = (info.st_dev, info.st_ino)
        self.operations = json.loads(canonical(configuration["operations"]))
        if not isinstance(self.operations, dict) or not self.operations:
            raise ValueError("database operations must be registered by the owner")
        for name, operation in self.operations.items():
            if not isinstance(name, str) or not name or not isinstance(operation, dict) or set(operation) != {"sql", "table", "parameters", "max_rows"}:
                raise ValueError("invalid database operation registration")
            if not isinstance(operation["table"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", operation["table"]):
                raise ValueError("invalid registered table")
            if type(operation["max_rows"]) is not int or not 1 <= operation["max_rows"] <= 10000:
                raise ValueError("operation max_rows must be between 1 and 10000")
            if not isinstance(operation["sql"], str) or len(operation["sql"]) > 16384 or not re.match(r"\s*(?:UPDATE|DELETE)\b", operation["sql"], re.I):
                raise ValueError("only registered UPDATE/DELETE statements are supported")
            parameters = operation["parameters"]
            if not isinstance(parameters, list) or len(parameters) > 32 or not all(isinstance(p, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", p) for p in parameters) or len(set(parameters)) != len(parameters):
                raise ValueError("invalid parameter names")

    def _connect(self, *, readonly=False):
        current = self.path.stat()
        if self.path.is_symlink() or current.st_nlink != 1 or (current.st_dev, current.st_ino) != self.identity:
            raise ValueError("database identity changed")
        connection = sqlite3.connect("file:" + quote(str(self.path), safe="/") + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=5)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _arguments(self, name, parameters):
        if name not in self.operations:
            raise ValueError("database operation is not registered")
        operation = self.operations[name]
        if not isinstance(parameters, dict) or set(parameters) != set(operation["parameters"]):
            raise ValueError("parameters do not match the registered operation")
        for value in parameters.values():
            if value is not None and type(value) not in {str, int, float, bool}:
                raise ValueError("parameters must be scalar JSON values")
            if isinstance(value, str) and len(value) > 4096 or isinstance(value, float) and not math.isfinite(value):
                raise ValueError("parameter exceeds limits")
        return operation

    @staticmethod
    def _snapshot(connection, table):
        schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        # Views, triggers, virtual tables and WITHOUT ROWID layouts are unsupported.
        row = connection.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (table,)).fetchone()
        if row is None or row[0] != "table" or re.search(r"\b(VIRTUAL|WITHOUT\s+ROWID)\b", row[1], re.I):
            raise ValueError("maintenance requires a regular rowid table")
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)).fetchone():
            raise ValueError("maintenance of tables with triggers is unsupported")
        if any(row[1].lower() in {"rowid", "oid", "_rowid_"} for row in connection.execute(f'PRAGMA table_info("{table}")')):
            raise ValueError("tables shadowing SQLite row identity are unsupported")
        cursor = connection.execute(f'SELECT rowid,* FROM "{table}" ORDER BY rowid LIMIT 10001')
        rows = cursor.fetchall()
        if len(rows) > 10000:
            raise ValueError("table exceeds the bounded maintenance profile (10000 rows)")
        try:
            encoded = canonical({"schema": schema, "rows": rows})
        except (ValueError, TypeError) as exc:
            raise ValueError("table contains unsupported non-JSON values") from exc
        if len(encoded.encode()) > MAX_BYTES:
            raise ValueError("table exceeds the bounded maintenance profile (1 MiB)")
        return {"sha256": digest(encoded.encode()), "columns": [x[0] for x in cursor.description], "rows": rows}

    @staticmethod
    def _apply(connection, operation, parameters):
        table = operation["table"]
        def authorize(code, arg1, arg2, database, source):
            if source is not None or database not in (None, "main"):
                return sqlite3.SQLITE_DENY
            if code in {sqlite3.SQLITE_READ, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}:
                return sqlite3.SQLITE_OK if arg1 == table else sqlite3.SQLITE_DENY
            if code == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if code == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in {"lower", "upper", "length", "coalesce", "abs", "trim"}:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        # Bound VM work as well as result size. This is not a query cost estimator.
        ticks = [0]
        def progress():
            ticks[0] += 1
            return ticks[0] > 1000
        connection.set_authorizer(authorize)
        connection.set_progress_handler(progress, 1000)
        before = connection.total_changes
        try:
            connection.execute(operation["sql"], parameters)
        finally:
            connection.set_authorizer(None)
            connection.set_progress_handler(None, 0)
        count = connection.total_changes - before
        if count > operation["max_rows"]:
            raise ValueError("database row limit exceeded; transaction not committed")
        return count

    def preview(self, name: str, parameters: dict) -> dict:
        operation = self._arguments(name, parameters)
        with closing(self._connect(readonly=True)) as source, closing(sqlite3.connect(":memory:", isolation_level=None)) as private:
            if source.execute("PRAGMA page_count").fetchone()[0] * source.execute("PRAGMA page_size").fetchone()[0] > 64 * MAX_BYTES:
                raise ValueError("database exceeds the 64 MiB preview profile")
            deadline = time.monotonic() + 5
            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise ValueError("database preview backup timed out")
            source.backup(private, pages=64, progress=progress)
            private.execute("PRAGMA foreign_keys=ON")
            private.execute("PRAGMA trusted_schema=OFF")
            before = self._snapshot(private, operation["table"])
            count = self._apply(private, operation, parameters)
            after = self._snapshot(private, operation["table"])
        old = {row[0]: row for row in before["rows"]}
        new = {row[0]: row for row in after["rows"]}
        changes = [{"before": old[k], "after": new.get(k)} for k in old if old[k] != new.get(k)]
        return {"database": str(self.path), "identity": list(self.identity), "operation": name,
                "table": operation["table"], "sql": operation["sql"], "parameters": parameters,
                "before_sha256": before["sha256"], "after_sha256": after["sha256"],
                "rows_affected": count, "columns": before["columns"], "sample_changes": changes[:10]}

    def execute(self, plan: dict) -> dict:
        operation = self._arguments(plan["operation"], plan["parameters"])
        if plan["database"] != str(self.path) or plan["identity"] != list(self.identity) or plan["sql"] != operation["sql"]:
            raise ValueError("database execution binding changed")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                before = self._snapshot(connection, operation["table"])
                if before["sha256"] != plan["before_sha256"]:
                    raise ValueError("database changed after preview; review a fresh plan")
                count = self._apply(connection, operation, plan["parameters"])
                after = self._snapshot(connection, operation["table"])
                if count != plan["rows_affected"] or after["sha256"] != plan["after_sha256"]:
                    raise ValueError("database effect differs from approved preview; rolled back")
                try:
                    connection.commit()
                except sqlite3.Error as exc:
                    raise ExecutionUncertain("database commit outcome is uncertain; inspect database before reconciliation") from exc
            except BaseException:
                connection.rollback()
                raise
        return {"database": str(self.path), "table": operation["table"], "rows_affected": count,
                "before_sha256": before["sha256"], "after_sha256": after["sha256"], "transaction": "committed"}
