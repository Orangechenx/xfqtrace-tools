from __future__ import annotations

"""SQLite trace 索引和查询辅助函数。"""

import hashlib
import os
import sqlite3
import tempfile
from collections.abc import Iterable
from contextlib import closing
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .trace_io import TraceLine, _reg_canonical, iter_raw_lines, parse_line
from .trace_memory import LOAD_OPS, STORE_OPS, _get_mem_addr
from .trace_search import _match_insn_pattern

SCHEMA_VERSION = 2
IMPORT_BATCH_SIZE = 1000
MAX_SEQUENCE_PARTS = 10


def _sqlite_int(value: int | None) -> int | None:
    """SQLite INTEGER 是 signed 64-bit，超出范围的无符号值转为 signed64。"""
    if value is None:
        return None
    if -(1 << 63) <= value <= (1 << 63) - 1:
        return value
    if 0 <= value <= (1 << 64) - 1:
        return value - (1 << 64)
    return value


def _sqlite_addr(value: Any) -> int | None:
    """SQL 辅助函数：把文本/整数地址转换为索引库里的 signed64 表示。"""
    if value is None:
        return None
    if isinstance(value, int):
        return _sqlite_int(value)
    raw = str(value).strip()
    if not raw:
        return None
    return _sqlite_int(int(raw, 0))


def _sqlite_hex(value: Any) -> str | None:
    """SQL 辅助函数：把 signed64 地址显示为 unsigned 十六进制文本。"""
    if value is None:
        return None
    raw_value = int(str(value), 0) if not isinstance(value, int) else value
    if raw_value < 0:
        raw_value += 1 << 64
    return hex(raw_value)


def _open(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def _split_insn(insn: str) -> tuple[str, str]:
    stripped = insn.strip()
    if not stripped:
        return "", ""
    parts = stripped.split(maxsplit=1)
    opcode = parts[0].lower()
    operands = parts[1] if len(parts) > 1 else ""
    return opcode, operands


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trace_file (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            sha256 TEXT,
            imported_at TEXT NOT NULL,
            line_count INTEGER NOT NULL DEFAULT 0,
            parsed_count INTEGER NOT NULL DEFAULT 0,
            parse_failed_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS insn (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            line_no INTEGER NOT NULL,
            module TEXT NOT NULL,
            address INTEGER NOT NULL,
            address_uhex TEXT NOT NULL,
            offset INTEGER NOT NULL,
            offset_uhex TEXT NOT NULL,
            opcode TEXT NOT NULL,
            operands TEXT,
            insn TEXT NOT NULL,
            raw TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reg_access (
            insn_id INTEGER NOT NULL,
            reg TEXT NOT NULL,
            before_value INTEGER,
            after_value INTEGER,
            changed INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (insn_id, reg)
        );

        CREATE TABLE IF NOT EXISTS mem_access (
            insn_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            address INTEGER,
            address_uhex TEXT,
            size INTEGER,
            parse_ok INTEGER NOT NULL DEFAULT 0,
            expr TEXT
        );

        CREATE TABLE IF NOT EXISTS parse_error (
            file_id INTEGER NOT NULL,
            line_no INTEGER NOT NULL,
            raw TEXT NOT NULL,
            reason TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )


def _create_indexes(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_insn_file_line ON insn(file_id, line_no);
        CREATE INDEX IF NOT EXISTS idx_insn_opcode ON insn(opcode);
        CREATE INDEX IF NOT EXISTS idx_insn_module_addr ON insn(module, address);
        CREATE INDEX IF NOT EXISTS idx_insn_addr_uhex ON insn(address_uhex);
        CREATE INDEX IF NOT EXISTS idx_reg_access_reg_changed ON reg_access(reg, changed, insn_id);
        CREATE INDEX IF NOT EXISTS idx_reg_access_value ON reg_access(reg, after_value);
        CREATE INDEX IF NOT EXISTS idx_mem_access_addr ON mem_access(kind, address);
        CREATE INDEX IF NOT EXISTS idx_mem_access_addr_uhex ON mem_access(kind, address_uhex);
        """
    )


def _clear_existing(conn: sqlite3.Connection) -> None:
    for table in ("parse_error", "mem_access", "reg_access", "insn", "trace_file"):
        conn.execute(f"DELETE FROM {table}")


def _collect_regs(insn_id: int, tl: TraceLine) -> list[tuple[Any, ...]]:
    regs = sorted({_reg_canonical(reg) for reg in (*tl.regs_before.keys(), *tl.regs_after.keys())})
    rows: list[tuple[Any, ...]] = []
    for reg in regs:
        before = _lookup_trace_reg(tl.regs_before, reg)
        after = _lookup_trace_reg(tl.regs_after, reg)
        changed = int(after is not None and before != after)
        rows.append((insn_id, reg, _sqlite_int(before), _sqlite_int(after), changed))
    return rows


def _lookup_trace_reg(regs: dict[str, int], reg: str) -> int | None:
    if reg in regs:
        return regs[reg]
    canon = _reg_canonical(reg)
    if canon in regs:
        return regs[canon]
    if canon.startswith("x"):
        alt = f"w{canon[1:]}"
        if alt in regs:
            return regs[alt]
    return None


def _mem_expr(insn: str) -> str:
    start = insn.find("[")
    end = insn.find("]", start)
    if start < 0 or end < start:
        return ""
    return insn[start:end + 1]


def _infer_mem_size(opcode: str, operands: str) -> int | None:
    if opcode in {"strb", "ldrb", "sturb", "ldurb"}:
        return 1
    if opcode in {"strh", "ldrh", "sturh", "ldurh"}:
        return 2
    if opcode in {"stp", "ldp"}:
        return 16
    if opcode == "ldrsw":
        return 4
    first = operands.split(",", 1)[0].strip()
    if first.startswith("w"):
        return 4
    if first.startswith("x"):
        return 8
    return None


def _collect_mem_access(insn_id: int, tl: TraceLine, opcode: str, operands: str) -> list[tuple[Any, ...]]:
    kind = ""
    if opcode in STORE_OPS:
        kind = "write"
    elif opcode in LOAD_OPS:
        kind = "read"
    if not kind:
        return []

    address = _get_mem_addr(tl.insn, tl.regs_before)
    return [
        (
            insn_id,
            kind,
            _sqlite_int(address),
            _sqlite_hex(address),
            _infer_mem_size(opcode, operands),
            int(address is not None),
            _mem_expr(tl.insn),
        )
    ]


def _flush_batches(
    conn: sqlite3.Connection,
    insn_rows: list[tuple[Any, ...]],
    reg_rows: list[tuple[Any, ...]],
    mem_rows: list[tuple[Any, ...]],
    parse_error_rows: list[tuple[Any, ...]],
) -> None:
    if insn_rows:
        conn.executemany(
            """
            INSERT INTO insn(id, file_id, line_no, module, address, address_uhex,
                             offset, offset_uhex, opcode, operands, insn, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            insn_rows,
        )
        insn_rows.clear()
    if reg_rows:
        conn.executemany(
            """
            INSERT INTO reg_access(insn_id, reg, before_value, after_value, changed)
            VALUES (?, ?, ?, ?, ?)
            """,
            reg_rows,
        )
        reg_rows.clear()
    if mem_rows:
        conn.executemany(
            """
            INSERT INTO mem_access(insn_id, kind, address, address_uhex, size, parse_ok, expr)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            mem_rows,
        )
        mem_rows.clear()
    if parse_error_rows:
        conn.executemany(
            "INSERT INTO parse_error(file_id, line_no, raw, reason) VALUES (?, ?, ?, ?)",
            parse_error_rows,
        )
        parse_error_rows.clear()


def index_trace(path: str | Path, db_path: str | Path | None = None, *, replace: bool = False) -> dict[str, Any]:
    """将 trace 文本或 .lz4 文件流式导入 SQLite 索引库。"""
    trace_path = Path(path)
    if not trace_path.exists() or not trace_path.is_file():
        raise FileNotFoundError(f"trace 文件不存在: {trace_path}")

    db = Path(db_path) if db_path else trace_path.with_suffix(".db")
    if db.exists() and not replace:
        raise FileExistsError(f"索引库已存在，如需覆盖请使用 --replace: {db}")
    db.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix=f".{db.name}.", suffix=".tmp", dir=db.parent)
    os.close(fd)
    temp_db = Path(temp_name)
    try:
        with closing(_open(temp_db)) as conn:
            conn.execute("PRAGMA journal_mode=MEMORY")
            conn.execute("PRAGMA synchronous=OFF")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA locking_mode=EXCLUSIVE")
            with conn:
                _init_schema(conn)
                if replace:
                    _clear_existing(conn)

                cursor = conn.execute(
                    """
                    INSERT INTO trace_file(path, size, sha256, imported_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(trace_path.resolve()),
                        trace_path.stat().st_size,
                        _hash_file(trace_path),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                file_id = int(cursor.lastrowid)

                line_count = 0
                parsed_count = 0
                parse_failed_count = 0
                next_insn_id = 1
                insn_rows: list[tuple[Any, ...]] = []
                reg_rows: list[tuple[Any, ...]] = []
                mem_rows: list[tuple[Any, ...]] = []
                parse_error_rows: list[tuple[Any, ...]] = []

                for line_no, line in iter_raw_lines(paths=[trace_path]):
                    line_count += 1
                    tl = parse_line(line, line_no)
                    if tl is None:
                        continue
                    if tl.is_call or tl.is_ret:
                        continue
                    if not tl.is_instruction:
                        parse_failed_count += 1
                        parse_error_rows.append((file_id, line_no, tl.raw, "格式无法解析"))
                        if len(parse_error_rows) >= IMPORT_BATCH_SIZE:
                            _flush_batches(conn, insn_rows, reg_rows, mem_rows, parse_error_rows)
                        continue

                    opcode, operands = _split_insn(tl.insn)
                    insn_id = next_insn_id
                    next_insn_id += 1
                    insn_rows.append(
                        (
                            insn_id,
                            file_id,
                            tl.line_no,
                            tl.module,
                            _sqlite_int(tl.address),
                            _sqlite_hex(tl.address),
                            _sqlite_int(tl.offset),
                            _sqlite_hex(tl.offset),
                            opcode,
                            operands,
                            tl.insn,
                            tl.raw,
                        )
                    )
                    parsed_count += 1
                    reg_rows.extend(_collect_regs(insn_id, tl))
                    mem_rows.extend(_collect_mem_access(insn_id, tl, opcode, operands))

                    if len(insn_rows) >= IMPORT_BATCH_SIZE:
                        _flush_batches(conn, insn_rows, reg_rows, mem_rows, parse_error_rows)

                _flush_batches(conn, insn_rows, reg_rows, mem_rows, parse_error_rows)

                conn.execute(
                    """
                    UPDATE trace_file
                    SET line_count = ?, parsed_count = ?, parse_failed_count = ?
                    WHERE id = ?
                    """,
                    (line_count, parsed_count, parse_failed_count, file_id),
                )
                _create_indexes(conn)

        os.replace(temp_db, db)
    except Exception:
        temp_db.unlink(missing_ok=True)
        raise

    return {
        "db": str(db),
        "input": str(trace_path),
        "file_id": file_id,
        "line_count": line_count,
        "parsed_count": parsed_count,
        "parse_failed_count": parse_failed_count,
    }


def _ensure_select(sql: str) -> str:
    stripped = sql.strip()
    normalized = stripped.lower()
    if not normalized.startswith("select") and not normalized.startswith("with"):
        raise ValueError("只允许只读 SELECT 查询")
    if ";" in stripped.rstrip(";"):
        raise ValueError("只允许单条只读 SELECT 查询")
    return stripped.rstrip(";")


def query_sql(db_path: str | Path, sql: str, params: Iterable[Any] = (), *, limit: int = 200) -> list[dict[str, Any]]:
    """执行只读 SELECT 查询。"""
    safe_sql = _ensure_select(sql)
    limited_sql = safe_sql
    if limit > 0 and " limit " not in f" {safe_sql.lower()} ":
        limited_sql = f"{safe_sql} LIMIT {int(limit)}"
    with closing(_open(db_path)) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.create_function("xfq_addr", 1, _sqlite_addr)
        conn.create_function("xfq_hex", 1, _sqlite_hex)
        return [_row_to_dict(row) for row in conn.execute(limited_sql, tuple(params))]


def _insn_select(where: str, order: str = "i.line_no", limit: int = 50) -> str:
    return f"""
        SELECT i.id, i.file_id, i.line_no, i.module, i.address, i.offset,
               i.opcode, i.operands, i.insn, i.raw
        FROM insn i
        {where}
        ORDER BY {order}
        LIMIT {int(limit)}
    """


def query_reg(
    db_path: str | Path,
    *,
    write: str | None = None,
    reg: str | None = None,
    changed: bool | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """查询寄存器访问。write 表示查询 changed=1 的写入。"""
    target = write or reg
    if not target:
        raise ValueError("请指定 --write 或 --reg")
    canonical = _reg_canonical(target)
    changed_value = 1 if write or changed else 0
    sql = _insn_select(
        "JOIN reg_access r ON r.insn_id = i.id WHERE r.reg = ? AND r.changed = ?",
        limit=limit,
    )
    with closing(_open(db_path)) as conn:
        return [_row_to_dict(row) for row in conn.execute(sql, (canonical, changed_value))]


def query_op(
    db_path: str | Path,
    *,
    opcode: str,
    module: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """按 opcode 和可选模块名查询指令。"""
    clauses = ["i.opcode = ?"]
    params: list[Any] = [opcode.lower()]
    if module:
        clauses.append("i.module LIKE ?")
        params.append(f"%{module}%")
    sql = _insn_select(f"WHERE {' AND '.join(clauses)}", limit=limit)
    with closing(_open(db_path)) as conn:
        return [_row_to_dict(row) for row in conn.execute(sql, params)]


def _rows_to_trace_results(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "line_no": row["line_no"],
            "module": row["module"],
            "address": _sqlite_hex(row["address"]),
            "offset": _sqlite_hex(row["offset"]),
            "insn": row["insn"],
            "raw": row["raw"],
        }
        for row in rows
    ]


def _fetch_insn_window(conn: sqlite3.Connection, file_id: int, start_line: int, end_line: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, file_id, line_no, module, address, offset, opcode, operands, insn, raw
        FROM insn
        WHERE file_id = ? AND line_no BETWEEN ? AND ?
        ORDER BY line_no
        """,
        (file_id, start_line, end_line),
    )
    return [_row_to_dict(row) for row in rows]


def _fetch_insn_sequence_by_id(conn: sqlite3.Connection, file_id: int, start_id: int, count: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, file_id, line_no, module, address, offset, opcode, operands, insn, raw
        FROM insn
        WHERE file_id = ? AND id >= ?
        ORDER BY id
        LIMIT ?
        """,
        (file_id, start_id, count),
    )
    return [_row_to_dict(row) for row in rows]


def _fetch_context_before(conn: sqlite3.Connection, file_id: int, start_id: int, context: int) -> list[dict[str, Any]]:
    if context <= 0:
        return []
    rows = conn.execute(
        """
        SELECT id, file_id, line_no, module, address, offset, opcode, operands, insn, raw
        FROM insn
        WHERE file_id = ? AND id < ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (file_id, start_id, context),
    )
    return list(reversed([_row_to_dict(row) for row in rows]))


def _fetch_context_after(conn: sqlite3.Connection, file_id: int, end_id: int, context: int) -> list[dict[str, Any]]:
    if context <= 0:
        return []
    rows = conn.execute(
        """
        SELECT id, file_id, line_no, module, address, offset, opcode, operands, insn, raw
        FROM insn
        WHERE file_id = ? AND id > ?
        ORDER BY id
        LIMIT ?
        """,
        (file_id, end_id, context),
    )
    return [_row_to_dict(row) for row in rows]


def _fixed_opcode(pattern: str) -> str:
    opcode, _ = _split_insn(pattern)
    if not opcode or "*" in opcode or "?" in opcode:
        return ""
    return opcode.lower()


def _sequence_candidate_sql(parts: list[str]) -> tuple[str, list[str]]:
    joins = [
        f"JOIN insn s{idx} ON s{idx}.file_id = s0.file_id AND s{idx}.id = s0.id + {idx}"
        for idx in range(1, len(parts))
    ]
    clauses: list[str] = []
    params: list[str] = []
    for idx, part in enumerate(parts):
        opcode = _fixed_opcode(part)
        if opcode:
            clauses.append(f"s{idx}.opcode = ?")
            params.append(opcode)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT s0.id, s0.file_id, s0.line_no, s0.module, s0.address, s0.offset,
               s0.opcode, s0.operands, s0.insn, s0.raw
        FROM insn s0
        {' '.join(joins)}
        {where}
        ORDER BY s0.file_id, s0.id
    """
    return sql, params


def query_sequence(
    db_path: str | Path,
    pattern: str,
    *,
    context: int = 0,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """基于索引查询相邻指令序列，先用 opcode SQL 预筛，再做完整模式匹配。"""
    parts = [part.strip() for part in pattern.split(";") if part.strip()]
    if not parts:
        raise ValueError("序列模式不能为空")
    if len(parts) > MAX_SEQUENCE_PARTS:
        raise ValueError(
            f"序列长度过长 ({len(parts)} 段)，当前索引查询最多支持 {MAX_SEQUENCE_PARTS} 段；"
            "请缩短模式或先用 query/sql 缩小范围。"
        )

    results: list[dict[str, Any]] = []
    with closing(_open(db_path)) as conn:
        candidates_sql, params = _sequence_candidate_sql(parts)
        for candidate in conn.execute(candidates_sql, params):
            base = _row_to_dict(candidate)
            seq_rows = _fetch_insn_sequence_by_id(conn, base["file_id"], base["id"], len(parts))
            if len(seq_rows) != len(parts):
                continue
            if not all(_match_insn_pattern(row["insn"], pat) for row, pat in zip(seq_rows, parts)):
                continue

            before = _fetch_context_before(conn, base["file_id"], base["id"], max(0, context))
            after = _fetch_context_after(conn, base["file_id"], seq_rows[-1]["id"], max(0, context))
            results.append({
                "start_line": seq_rows[0]["line_no"],
                "end_line": seq_rows[-1]["line_no"],
                "count": len(seq_rows),
                "adjacent": True,
                "context_before": _rows_to_trace_results(before),
                "context_after": _rows_to_trace_results(after),
                "sequence": _rows_to_trace_results(seq_rows),
            })
            if limit and len(results) >= limit:
                break
    return results
