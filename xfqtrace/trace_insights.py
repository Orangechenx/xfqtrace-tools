from __future__ import annotations

"""面向算法还原的 trace 洞察能力。

这些能力复用现有 SQLite 索引，不依赖 GUI；适合 CLI 和 MCP 共享。
"""

import hashlib
import re
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path
from typing import Any

from .trace_index import _hash_file, _open, _row_to_dict, _sqlite_addr, _sqlite_hex, index_trace
from .trace_io import _reg_canonical, iter_raw_lines, parse_line

STRING_RE = re.compile(r"(?P<quote>['\"])(?P<value>[ -~]{4,}?)(?P=quote)")
REG_TOKEN_RE = re.compile(r"\b(?:x(?:[0-2]?\d|30)|w(?:[0-2]?\d|30)|sp|lr|nzcv)\b", re.IGNORECASE)

CRYPTO_SIGNATURES: tuple[dict[str, Any], ...] = (
    {"algorithm": "AES", "kind": "opcode", "regex": re.compile(r"\b(?:aese|aesd|aesmc|aesimc)\b", re.I)},
    {"algorithm": "SHA", "kind": "opcode", "regex": re.compile(r"\bsha(?:1|256)", re.I)},
    {"algorithm": "CRC32", "kind": "opcode", "regex": re.compile(r"\bcrc32", re.I)},
    {"algorithm": "TEA/XXTEA", "kind": "constant", "regex": re.compile(r"0x(?:9e3779b9|61c88647)\b", re.I)},
    {"algorithm": "MD5", "kind": "constant", "regex": re.compile(r"0x(?:d76aa478|e8c7b756|242070db|c1bdceee)\b", re.I)},
    {"algorithm": "SHA-256", "kind": "constant", "regex": re.compile(r"0x(?:6a09e667|bb67ae85|3c6ef372|a54ff53a)\b", re.I)},
    {"algorithm": "RC4", "kind": "text", "regex": re.compile(r"\b(?:rc4|sbox|ksa|prga)\b", re.I)},
)


def ensure_index_cache(
    input_path: str | Path,
    *,
    cache_dir: str | Path | None = None,
    db_path: str | Path | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    """为 trace 建立可复用索引；匹配现有缓存时直接返回。"""
    trace_path = Path(input_path).expanduser().resolve()
    if not trace_path.exists() or not trace_path.is_file():
        raise FileNotFoundError(f"trace 文件不存在: {trace_path}")

    db = Path(db_path).expanduser().resolve() if db_path else _default_cache_db(trace_path, cache_dir)
    db.parent.mkdir(parents=True, exist_ok=True)

    if db.exists() and not replace and _index_matches_trace(db, trace_path):
        summary = _index_summary(db)
        return {
            "input": str(trace_path),
            "db": str(db),
            "reused": True,
            **summary,
        }

    summary = index_trace(trace_path, db_path=db, replace=True)
    return {
        **summary,
        "db": str(db),
        "input": str(trace_path),
        "reused": False,
    }


def _default_cache_db(trace_path: Path, cache_dir: str | Path | None) -> Path:
    root = Path(cache_dir).expanduser().resolve() if cache_dir else trace_path.parent / ".xfq-index"
    stat = trace_path.stat()
    key = hashlib.sha256(
        f"{trace_path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}".encode("utf-8")
    ).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", trace_path.name)
    return root / f"{stem}.{key}.db"


def _index_matches_trace(db_path: Path, trace_path: Path) -> bool:
    try:
        with closing(_open(db_path)) as conn:
            row = conn.execute(
                """
                SELECT path, size, sha256
                FROM trace_file
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
            return bool(
                row
                and Path(str(row["path"])).resolve() == trace_path.resolve()
                and int(row["size"]) == trace_path.stat().st_size
                and str(row["sha256"] or "") == _hash_file(trace_path)
            )
    except (OSError, sqlite3.DatabaseError):
        return False


def _index_summary(db_path: str | Path) -> dict[str, Any]:
    with closing(_open(db_path)) as conn:
        row = conn.execute(
            """
            SELECT id AS file_id, line_count, parsed_count, parse_failed_count
            FROM trace_file
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    if not row:
        return {"file_id": None, "line_count": 0, "parsed_count": 0, "parse_failed_count": 0}
    return _row_to_dict(row)


def get_trace_lines(db_path: str | Path, *, start_line: int = 1, count: int = 50) -> dict[str, Any]:
    """从索引库按行号读取指令窗口。"""
    start = max(1, int(start_line))
    limit = max(1, min(int(count), 1000))
    with closing(_open(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT id, file_id, line_no, module, address, offset, opcode, operands, insn, raw
            FROM insn
            WHERE line_no >= ?
            ORDER BY line_no
            LIMIT ?
            """,
            (start, limit),
        ).fetchall()
    lines = [_insn_result(_row_to_dict(row)) for row in rows]
    return {"start_line": start, "count": len(lines), "lines": lines}


def query_defuse(
    db_path: str | Path,
    *,
    reg: str | None = None,
    address: str | int | None = None,
    line: int | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """查询寄存器或内存地址的定义点和使用点。"""
    if reg:
        return _query_reg_defuse(db_path, reg=reg, line=line, limit=limit)
    if address is not None:
        return _query_mem_defuse(db_path, address=address, line=line, limit=limit)
    raise ValueError("请指定 reg 或 address")


def _query_reg_defuse(db_path: str | Path, *, reg: str, line: int | None, limit: int) -> dict[str, Any]:
    canonical = _reg_canonical(reg)
    line_filter_def = "AND i.line_no <= ?" if line else ""
    line_filter_use = "AND i.line_no >= ?" if line else ""
    def_params: list[Any] = [canonical]
    use_params: list[Any] = [canonical]
    if line:
        def_params.append(int(line))
        use_params.append(int(line))
    with closing(_open(db_path)) as conn:
        defs = conn.execute(
            f"""
            SELECT i.id, i.file_id, i.line_no, i.module, i.address, i.offset,
                   i.opcode, i.operands, i.insn, i.raw,
                   r.before_value, r.after_value
            FROM reg_access r
            JOIN insn i ON i.id = r.insn_id
            WHERE r.reg = ? AND r.changed = 1 {line_filter_def}
            ORDER BY i.line_no DESC
            LIMIT ?
            """,
            (*def_params, int(limit)),
        ).fetchall()
        uses = conn.execute(
            f"""
            SELECT i.id, i.file_id, i.line_no, i.module, i.address, i.offset,
                   i.opcode, i.operands, i.insn, i.raw,
                   r.before_value, r.after_value
            FROM reg_access r
            JOIN insn i ON i.id = r.insn_id
            WHERE r.reg = ? AND r.changed = 0 AND r.before_value IS NOT NULL {line_filter_use}
            ORDER BY i.line_no ASC
            LIMIT ?
            """,
            (*use_params, int(limit)),
        ).fetchall()
    return {
        "target": {"reg": canonical},
        "definitions": [_access_result(_row_to_dict(row)) for row in defs],
        "uses": [_access_result(_row_to_dict(row)) for row in uses],
    }


def _query_mem_defuse(db_path: str | Path, *, address: str | int, line: int | None, limit: int) -> dict[str, Any]:
    target_addr = _sqlite_addr(address)
    line_filter_def = "AND i.line_no <= ?" if line else ""
    line_filter_use = "AND i.line_no >= ?" if line else ""
    def_params: list[Any] = [target_addr]
    use_params: list[Any] = [target_addr]
    if line:
        def_params.append(int(line))
        use_params.append(int(line))
    with closing(_open(db_path)) as conn:
        defs = conn.execute(
            f"""
            SELECT i.id, i.file_id, i.line_no, i.module, i.address, i.offset,
                   i.opcode, i.operands, i.insn, i.raw,
                   m.address AS mem_address, m.size, m.expr
            FROM mem_access m
            JOIN insn i ON i.id = m.insn_id
            WHERE m.address = ? AND m.kind = 'write' AND m.parse_ok = 1 {line_filter_def}
            ORDER BY i.line_no DESC
            LIMIT ?
            """,
            (*def_params, int(limit)),
        ).fetchall()
        uses = conn.execute(
            f"""
            SELECT i.id, i.file_id, i.line_no, i.module, i.address, i.offset,
                   i.opcode, i.operands, i.insn, i.raw,
                   m.address AS mem_address, m.size, m.expr
            FROM mem_access m
            JOIN insn i ON i.id = m.insn_id
            WHERE m.address = ? AND m.kind = 'read' AND m.parse_ok = 1 {line_filter_use}
            ORDER BY i.line_no ASC
            LIMIT ?
            """,
            (*use_params, int(limit)),
        ).fetchall()
    return {
        "target": {"address": _sqlite_hex(target_addr)},
        "definitions": [_access_result(_row_to_dict(row)) for row in defs],
        "uses": [_access_result(_row_to_dict(row)) for row in uses],
    }


def backward_slice(
    db_path: str | Path,
    *,
    reg: str | None = None,
    address: str | int | None = None,
    line: int | None = None,
    max_depth: int = 50,
) -> dict[str, Any]:
    """从目标寄存器向前追踪依赖，输出轻量 DAG。"""
    if not reg and address is None:
        raise ValueError("请指定 reg 或 address")
    if address is not None and not reg:
        return _backward_slice_memory(db_path, address=address, line=line, max_depth=max_depth)

    target_reg = _reg_canonical(str(reg))
    limit_line = int(line) if line else _max_line_no(db_path)
    consumers: dict[str, int | None] = {target_reg: None}
    nodes: dict[int, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    with closing(_open(db_path)) as conn:
        for insn in _iter_insns_reverse(conn, limit_line):
            accesses = _reg_accesses(conn, int(insn["id"]))
            writes = {row["reg"] for row in accesses if int(row["changed"]) == 1}
            reads = {
                row["reg"] for row in accesses
                if int(row["changed"]) == 0 and row["before_value"] is not None
            }
            matched = [reg_name for reg_name in sorted(writes) if reg_name in consumers]
            if not matched:
                continue

            node = _slice_node(insn, defines=matched, uses=sorted(reads))
            nodes[int(insn["id"])] = node
            for matched_reg in matched:
                consumer_id = consumers.pop(matched_reg)
                if consumer_id is not None and consumer_id in nodes:
                    consumer = nodes[consumer_id]
                    edges.append({
                        "reg": matched_reg,
                        "from": int(insn["id"]),
                        "to": consumer_id,
                        "from_line": int(insn["line_no"]),
                        "to_line": int(consumer["line_no"]),
                    })
            for read_reg in sorted(reads):
                consumers.setdefault(read_reg, int(insn["id"]))
            if len(nodes) >= max(1, int(max_depth)):
                break

    ordered_nodes = sorted(nodes.values(), key=lambda item: item["line_no"])
    ordered_edges = sorted(edges, key=lambda item: (item["from_line"], item["to_line"], item["reg"]))
    return {
        "target": {"reg": target_reg, "line": limit_line},
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "unresolved": sorted(consumers.keys()),
    }


def _backward_slice_memory(
    db_path: str | Path,
    *,
    address: str | int,
    line: int | None,
    max_depth: int,
) -> dict[str, Any]:
    defuse = query_defuse(db_path, address=address, line=line, limit=1)
    nodes = [
        {
            "id": item["id"],
            "line_no": item["line_no"],
            "module": item["module"],
            "address": item["address"],
            "offset": item["offset"],
            "insn": item["insn"],
            "defines": [defuse["target"]["address"]],
            "uses": _extract_regs_from_insn(item["insn"]),
        }
        for item in defuse["definitions"][:max(1, int(max_depth))]
    ]
    return {"target": defuse["target"], "nodes": nodes, "edges": [], "unresolved": []}


def extract_strings(
    *,
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
    min_length: int = 4,
    limit: int = 200,
) -> dict[str, Any]:
    """提取 trace 中可见字符串，并保留行号交叉引用。"""
    found: dict[str, dict[str, Any]] = {}
    for line_no, raw in _iter_source_lines(paths=paths, text=text):
        for match in STRING_RE.finditer(raw):
            value = match.group("value")
            if len(value) < min_length:
                continue
            item = found.setdefault(value, {"value": value, "length": len(value), "xrefs": []})
            item["xrefs"].append(_xref_from_raw(line_no, raw))
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break
    strings = sorted(found.values(), key=lambda item: (item["xrefs"][0]["line_no"], item["value"]))
    return {"matches": len(strings), "strings": strings}


def scan_crypto_signatures(
    *,
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """扫描常见 crypto opcode/常量线索。"""
    matches: list[dict[str, Any]] = []
    for line_no, raw in _iter_source_lines(paths=paths, text=text):
        for sig in CRYPTO_SIGNATURES:
            found = sig["regex"].search(raw)
            if not found:
                continue
            item = _xref_from_raw(line_no, raw)
            item.update({
                "algorithm": sig["algorithm"],
                "kind": sig["kind"],
                "pattern": found.group(0),
            })
            matches.append(item)
            if len(matches) >= limit:
                return {"matches": matches, "count": len(matches)}
    return {"matches": matches, "count": len(matches)}


def build_instruction_call_tree(
    *,
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
    max_events: int = 500,
) -> dict[str, Any]:
    """基于 hook call/ret 和 bl/blr/ret 指令生成轻量调用事件流。"""
    events: list[dict[str, Any]] = []
    depth = 0
    for line_no, raw in _iter_source_lines(paths=paths, text=text):
        stripped = raw.strip()
        event: dict[str, Any] | None = None
        if stripped.startswith("call func:"):
            event = {"line_no": line_no, "type": "call", "depth": depth, "name": stripped.split(":", 1)[1].strip(), "raw": stripped}
            depth += 1
        elif stripped.startswith("ret:"):
            depth = max(0, depth - 1)
            event = {"line_no": line_no, "type": "ret", "depth": depth, "name": stripped, "raw": stripped}
        else:
            tl = parse_line(raw, line_no)
            if tl and tl.is_instruction:
                opcode = tl.insn.split(maxsplit=1)[0].lower() if tl.insn.strip() else ""
                if opcode in {"bl", "blr"}:
                    event = {"line_no": line_no, "type": "call", "depth": depth, "name": tl.insn, "raw": tl.raw}
                    depth += 1
                elif opcode == "ret":
                    depth = max(0, depth - 1)
                    event = {"line_no": line_no, "type": "ret", "depth": depth, "name": tl.insn, "raw": tl.raw}
        if event:
            events.append(event)
        if len(events) >= max_events:
            break
    return {"events": events, "count": len(events)}


def _iter_source_lines(
    *,
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
) -> Iterable[tuple[int, str]]:
    if text is not None:
        for idx, line in enumerate(text.splitlines(), 1):
            yield idx, line
        return
    if paths is None:
        raise ValueError("必须提供 paths 或 text")
    yield from iter_raw_lines(paths=paths)


def _xref_from_raw(line_no: int, raw: str) -> dict[str, Any]:
    tl = parse_line(raw, line_no)
    if not tl:
        return {"line_no": line_no, "raw": raw.strip()}
    return {
        "line_no": line_no,
        "module": tl.module,
        "address": hex(tl.address) if tl.address is not None else "",
        "offset": hex(tl.offset) if tl.offset is not None else "",
        "insn": tl.insn,
        "raw": tl.raw,
    }


def _insn_result(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "file_id": row["file_id"],
        "line_no": row["line_no"],
        "module": row["module"],
        "address": _sqlite_hex(row["address"]),
        "offset": _sqlite_hex(row["offset"]),
        "opcode": row["opcode"],
        "operands": row.get("operands"),
        "insn": row["insn"],
        "raw": row["raw"],
    }


def _access_result(row: dict[str, Any]) -> dict[str, Any]:
    result = _insn_result(row)
    if "before_value" in row:
        result["before"] = _sqlite_hex(row["before_value"])
        result["after"] = _sqlite_hex(row["after_value"])
    if "mem_address" in row:
        result["mem_address"] = _sqlite_hex(row["mem_address"])
        result["size"] = row.get("size")
        result["expr"] = row.get("expr")
    return result


def _max_line_no(db_path: str | Path) -> int:
    with closing(_open(db_path)) as conn:
        row = conn.execute("SELECT COALESCE(MAX(line_no), 0) AS line_no FROM insn").fetchone()
    return int(row["line_no"]) if row else 0


def _iter_insns_reverse(conn: sqlite3.Connection, line_no: int) -> Iterable[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, file_id, line_no, module, address, offset, opcode, operands, insn, raw
        FROM insn
        WHERE line_no <= ?
        ORDER BY id DESC
        """,
        (line_no,),
    )
    for row in rows:
        yield _row_to_dict(row)


def _reg_accesses(conn: sqlite3.Connection, insn_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT reg, before_value, after_value, changed
        FROM reg_access
        WHERE insn_id = ?
        ORDER BY reg
        """,
        (insn_id,),
    )
    return [_row_to_dict(row) for row in rows]


def _slice_node(insn: dict[str, Any], *, defines: list[str], uses: list[str]) -> dict[str, Any]:
    return {
        "id": int(insn["id"]),
        "line_no": int(insn["line_no"]),
        "module": insn["module"],
        "address": _sqlite_hex(insn["address"]),
        "offset": _sqlite_hex(insn["offset"]),
        "insn": insn["insn"],
        "defines": defines,
        "uses": uses,
    }


def _extract_regs_from_insn(insn: str) -> list[str]:
    return sorted({_reg_canonical(match.group(0)) for match in REG_TOKEN_RE.finditer(insn)})
