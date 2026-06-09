from __future__ import annotations

"""轻量污点传播分析。"""

import re
from pathlib import Path

from .trace_io import iter_raw_lines, parse_line, resolve_trace_file, _reg_canonical
from .trace_memory import LOAD_OPS, STORE_OPS, _extract_regs, _get_mem_addr

ALU_OPS = {"add", "sub", "eor", "and", "orr", "bic", "orn",
           "lsl", "lsr", "asr", "mul", "udiv", "sdiv",
           "csel", "csinc", "csinv", "csneg", "cset",
           "madd", "msub", "smull", "umull", "smulh", "umulh",
           "movk", "adrp",
           "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw",
           "mov", "mvn", "neg", "lslv", "lsrv", "asrv", "ror", "rorv"}

SIMD_FP_OPS = {
    "ld1", "ld2", "ld3", "ld4", "st1", "st2", "st3", "st4",
    "dup", "ins", "umov", "smov", "ext", "tbl", "tbx",
    "zip1", "zip2", "uzip1", "uzip2", "trn1", "trn2",
    "movi", "fmov",
}
VECTOR_REG_RE = re.compile(r"\b(?:v|q|d)\d+(?:\.[0-9a-z]+)?\b", re.IGNORECASE)


def _split_opcode_operands(insn: str) -> tuple[str, str]:
    stripped = insn.strip()
    if not stripped:
        return "", ""
    parts = stripped.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _split_operands(operands: str) -> list[str]:
    """按顶层逗号拆分操作数，避免把 [x0, #8] 内部逗号拆开。"""
    result: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in operands:
        if ch == "[":
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            item = "".join(current).strip()
            if item:
                result.append(item)
            current = []
            continue
        current.append(ch)
    item = "".join(current).strip()
    if item:
        result.append(item)
    return result


def _data_operands_before_memory(operands: str) -> list[str]:
    """返回内存操作中 [addr] 之前的数据寄存器操作数。"""
    before_mem = operands.split("[", 1)[0].rstrip(" ,")
    return _split_operands(before_mem)


def _regs_from_operands(operands: list[str]) -> list[str]:
    regs: list[str] = []
    for operand in operands:
        regs.extend(_extract_regs(operand))
    return regs


def _reg_width(reg: str) -> int:
    if reg.startswith("w"):
        return 4
    if reg.startswith("x") or reg == "sp":
        return 8
    return 8


def _store_width(op: str, reg: str | None = None) -> int:
    if op in {"strb", "sturb"}:
        return 1
    if op in {"strh", "sturh"}:
        return 2
    return _reg_width(reg or "x0")


def _load_width(op: str, reg: str | None = None) -> int:
    if op in {"ldrb", "ldurb"}:
        return 1
    if op in {"ldrh", "ldurh"}:
        return 2
    if op == "ldrsw":
        return 4
    return _reg_width(reg or "x0")


def _is_simd_fp_instruction(op: str, operands: str) -> bool:
    opcode = op.lower()
    if opcode.startswith("f") or opcode in SIMD_FP_OPS:
        return True
    return bool(VECTOR_REG_RE.search(operands))


def taint_analysis(
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
    log_dir: str | Path | None = None,
    package: str = "",
    taint_regs: list[str] | None = None,
    taint_mem_range: tuple[int, int] | None = None,
    summary: bool = False,
) -> dict:
    """污点分析：标记输入，跟踪传播路径。

    Args:
        taint_regs: 初始标记的寄存器列表，如 ["x2"]
        taint_mem_range: 初始标记的内存地址范围 (start, end)
        summary: 只输出结论，不输出详细传播路径

    Returns:
        包含传播路径和结果的 dict
    """
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    # 参数校验（在早期返回之前检查）
    if taint_mem_range:
        start, end = taint_mem_range
        if end < start:
            raise ValueError(f"内存范围起始地址不能大于结束地址 ({hex(start)} > {hex(end)})")
        if end - start > 1_000_000:
            raise ValueError(
                f"内存范围过大 ({hex(start)}-{hex(end)}, {(end-start)/1024/1024:.1f} MB)。"
                f"请将范围缩小到 1MB 以内。"
            )

    # 污点状态
    reg_taint: dict[str, set[str]] = {}  # 寄存器 → {污点标签}
    mem_taint: dict[int, set[str]] = {}  # 绝对字节地址 → {污点标签}
    initial_mem_ranges: list[tuple[int, int, set[str]]] = []

    # 初始化污点标记
    if taint_regs:
        for r in taint_regs:
            reg_taint.setdefault(_reg_canonical(r), set()).add(f"input:{r}")

    if taint_mem_range:
        start, end = taint_mem_range
        initial_mem_ranges.append((start, end, {f"input:mem_{hex(start)}"}))

    # 传播链记录
    propagation: list[dict] = []
    total_instructions = 0
    unparsed_line_count = 0
    unparsed_samples: list[dict] = []
    unsupported_instruction_count = 0
    unsupported_samples: list[dict] = []

    def _mark_reg(reg: str, tags: set[str], source_insn: str, line_no: int) -> None:
        """合并寄存器污点并记录传播链，用于读改写指令。"""
        canon = _reg_canonical(reg)
        if not tags:
            return
        old = reg_taint.get(canon, set()).copy()
        reg_taint.setdefault(canon, set()).update(tags)
        new_tags = tags - old
        if new_tags:
            propagation.append({
                "type": "reg",
                "target": canon,
                "tags": list(new_tags),
                "insn": source_insn,
                "line_no": line_no,
            })

    def _set_reg(reg: str, tags: set[str], source_insn: str, line_no: int) -> None:
        """覆盖写寄存器污点；写 wN 时同步清理对应 xN 的旧污点。"""
        canon = _reg_canonical(reg)
        old = reg_taint.get(canon, set()).copy()
        new_tags = tags.copy()
        if new_tags:
            reg_taint[canon] = new_tags
        else:
            reg_taint.pop(canon, None)
        added = new_tags - old
        if added:
            propagation.append({
                "type": "reg",
                "target": canon,
                "tags": list(added),
                "insn": source_insn,
                "line_no": line_no,
            })

    def _mark_mem(addr: int, tags: set[str], source_insn: str, line_no: int) -> None:
        """标记内存并记录传播链。"""
        if not tags:
            return
        old = mem_taint.get(addr, set()).copy()
        mem_taint.setdefault(addr, set()).update(tags)
        new_tags = tags - old
        if new_tags:
            propagation.append({
                "type": "mem",
                "target": hex(addr),
                "tags": list(new_tags),
                "insn": source_insn,
                "line_no": line_no,
            })

    def _mark_mem_range(addr: int, size: int, tags: set[str], source_insn: str, line_no: int) -> None:
        """按字节标记内存污点，避免 strb/strh 污染相邻字节。"""
        for offset in range(max(1, size)):
            _mark_mem(addr + offset, tags, source_insn, line_no)

    def _get_reg_tags(reg: str) -> set[str]:
        return reg_taint.get(_reg_canonical(reg), set()).copy()

    def _get_mem_tags(addr: int) -> set[str]:
        tags = mem_taint.get(addr, set()).copy()
        for start, end, range_tags in initial_mem_ranges:
            if start <= addr < end:
                tags.update(range_tags)
        return tags

    def _get_mem_tags_range(addr: int, size: int) -> set[str]:
        tags: set[str] = set()
        for offset in range(max(1, size)):
            tags.update(_get_mem_tags(addr + offset))
        return tags

    def _iter_source_lines():
        nonlocal unparsed_line_count
        for raw_line_no, raw_line in iter_raw_lines(paths=paths, text=text):
            parsed = parse_line(raw_line, raw_line_no)
            if parsed is None:
                continue
            if parsed.is_call or parsed.is_ret:
                continue
            if not parsed.is_instruction:
                unparsed_line_count += 1
                if len(unparsed_samples) < 5:
                    unparsed_samples.append({"line_no": raw_line_no, "raw": parsed.raw})
                continue
            yield parsed

    for tl in _iter_source_lines():
        total_instructions += 1
        insn = tl.insn.strip()
        op, operands = _split_opcode_operands(insn)
        regs_before = tl.regs_before
        regs_after = tl.regs_after
        line_no = tl.line_no

        if not op:
            continue

        if _is_simd_fp_instruction(op, operands):
            unsupported_instruction_count += 1
            if len(unsupported_samples) < 5:
                unsupported_samples.append({
                    "line_no": line_no,
                    "opcode": op,
                    "insn": insn,
                })

        # ── 内存写: str/stp/stur → 标记目标内存 ──
        if op in STORE_OPS:
            # 提取写入的寄存器和目标地址
            mem_addr = _get_mem_addr(insn, regs_before)
            if mem_addr is not None:
                # 收集源寄存器的污点
                store_regs = _regs_from_operands(_data_operands_before_memory(operands))
                if op == "stp" and len(store_regs) >= 2:
                    # STP: 每个寄存器单独标记对应地址
                    tags_0 = _get_reg_tags(store_regs[0])
                    tags_1 = _get_reg_tags(store_regs[1])
                    width_0 = _reg_width(store_regs[0])
                    width_1 = _reg_width(store_regs[1])
                    if tags_0:
                        _mark_mem_range(mem_addr, width_0, tags_0, insn, line_no)
                    if tags_1:
                        _mark_mem_range(mem_addr + width_0, width_1, tags_1, insn, line_no)
                else:
                    # STR/STUR/STRB: 收集源寄存器的污点
                    all_tags: set[str] = set()
                    for sr in store_regs:
                        canon = _reg_canonical(sr)
                        if sr in regs_before or sr in regs_after or canon in regs_before or canon in regs_after:
                            all_tags.update(_get_reg_tags(sr))
                    if all_tags:
                        _mark_mem_range(mem_addr, _store_width(op, store_regs[0] if store_regs else None), all_tags, insn, line_no)
            continue

        # ── 内存读: ldr/ldp/ldur → 从内存继承污点 ──
        if op in LOAD_OPS:
            mem_addr = _get_mem_addr(insn, regs_before)
            if mem_addr is not None:
                dest_regs = _regs_from_operands(_data_operands_before_memory(operands))
                if op == "ldp" and len(dest_regs) >= 2:
                    # LDP: 每个目标寄存器继承对应地址的污点
                    width_0 = _reg_width(dest_regs[0])
                    width_1 = _reg_width(dest_regs[1])
                    tags_0 = _get_mem_tags_range(mem_addr, width_0)
                    tags_1 = _get_mem_tags_range(mem_addr + width_0, width_1)
                    _set_reg(dest_regs[0], tags_0, insn, line_no)
                    _set_reg(dest_regs[1], tags_1, insn, line_no)
                elif dest_regs:
                    mem_tags = _get_mem_tags_range(mem_addr, _load_width(op, dest_regs[0]))
                    _set_reg(dest_regs[0], mem_tags, insn, line_no)
            continue

        # ── ALU / mov: 结果继承所有源寄存器的污点 ──
        if op in ALU_OPS:
            operand_parts = _split_operands(operands)
            dest_regs = _regs_from_operands(operand_parts[:1])
            src_regs = _regs_from_operands(operand_parts[1:])
            if dest_regs and src_regs:
                dest = dest_regs[0]  # 第一个是目标
                all_src_tags: set[str] = set()
                for sr in src_regs:
                    # 检查该寄存器在执行前/后是否有值
                    if sr in regs_before or sr in regs_after:
                        all_src_tags.update(_get_reg_tags(sr))
                    # 检查 w/x 别名
                    alt = _reg_canonical(sr)
                    if alt != sr:
                        all_src_tags.update(_get_reg_tags(alt))
                _set_reg(dest, all_src_tags, insn, line_no)
            elif op == "movk" and dest_regs:
                # movk 是读改写，未建模半字粒度时保守保留目标旧污点。
                dest = dest_regs[0]
                existing = _get_reg_tags(dest)
                if existing:
                    _mark_reg(dest, existing, insn, line_no)
            elif op == "cset" and dest_regs:
                _set_reg(dest_regs[0], _get_reg_tags("nzcv"), insn, line_no)
            elif dest_regs:
                _set_reg(dest_regs[0], set(), insn, line_no)
            continue

        # ── 比较/测试指令（cmp, cmn, tst）：影响标志位 ──
        if op in {"cmp", "cmn", "tst"}:
            all_regs = _extract_regs(insn)
            all_src_tags = set()
            for sr in all_regs:
                all_src_tags.update(_get_reg_tags(sr))
            if all_src_tags:
                # 标记 NZCV 标志位
                _mark_reg("nzcv", all_src_tags, insn, line_no)
            continue

        # ── 条件跳转：不传播，但继续跟踪 ──
        # 什么都不做，只是继续

    # ── 收尾阶段：提取最终污点状态 ──
    final_reg_taint = {reg: list(tags) for reg, tags in reg_taint.items() if tags}
    final_mem_taint_details = {hex(addr): list(tags) for addr, tags in mem_taint.items() if tags}
    final_mem_ranges = [
        {"start": hex(start), "end": hex(end), "tags": list(tags)}
        for start, end, tags in initial_mem_ranges
        if tags
    ]
    final_mem_range_count = sum(max(0, end - start) for start, end, tags in initial_mem_ranges if tags)
    final_mem_taint_count = len(final_mem_taint_details) + final_mem_range_count

    # 判断返回值（x0）是否被污染
    ret_tainted = "x0" in reg_taint and bool(reg_taint["x0"])

    warnings = [
        "内存污点按字节地址记录；未知宽度指令和向量寄存器仍按保守规则处理。"
    ]
    if unparsed_line_count:
        warnings.append(
            f"trace 中有 {unparsed_line_count} 行非指令/异常行未参与污点传播，可能造成传播链间隙。"
        )
    if unsupported_instruction_count:
        warnings.append(
            f"发现 {unsupported_instruction_count} 条 SIMD/FP/向量类指令未建模传播，相关污点结果按保守缺口处理。"
        )

    result = {
        "total_instructions": total_instructions,
        "ret_tainted": ret_tainted,
        "ret_tags": list(reg_taint.get("x0", set())) if ret_tainted else [],
        "propagation_count": len(propagation),
        "taint_granularity": "byte_level",
        "unparsed_line_count": unparsed_line_count,
        "unparsed_samples": unparsed_samples,
        "unsupported_instruction_count": unsupported_instruction_count,
        "unsupported_instruction_samples": unsupported_samples,
        "result_register_taint_count": len(final_reg_taint),
        "result_memory_taint_count": final_mem_taint_count,
        "result_register_taint": final_reg_taint,
        "result_memory_taint": {} if summary else final_mem_taint_details,
        "result_memory_taint_ranges": final_mem_ranges,
        "warnings": warnings,
    }

    if not summary:
        result["propagation"] = propagation

    return result


def format_taint_result(result: dict, max_prop: int = 50) -> str:
    """格式化污点分析结果为人类可读文本。"""
    lines = []
    lines.append(f"污点分析结果 — {result['total_instructions']:,} 条指令")
    lines.append("")

    if result["ret_tainted"]:
        lines.append(f"  🎯 返回值 x0 被污染! (标签: {', '.join(result['ret_tags'])})")
    else:
        lines.append(f"  ✅ 返回值 x0 未被污染")

    lines.append(f"  传播链: {result['propagation_count']} 条")
    reg_count = result.get("result_register_taint_count", len(result["result_register_taint"]))
    mem_count = result.get("result_memory_taint_count", len(result["result_memory_taint"]))
    lines.append(f"  污染寄存器: {reg_count} 个")
    lines.append(f"  污染内存: {mem_count} 处")
    for warning in result.get("warnings", []):
        lines.append(f"  警告: {warning}")
    lines.append("")

    if result.get("propagation"):
        display_count = min(max(0, max_prop), len(result["propagation"]))
        lines.append(f"传播路径 (前 {display_count} 条):")
        lines.append("")
        for p in result["propagation"][:max_prop if max_prop > 0 else 0]:
            if p["type"] == "reg":
                lines.append(f"  L{p['line_no']:>6}  →  {p['target']:<6}  <- {', '.join(p['tags']):<30}  {p['insn']}")
            else:
                lines.append(f"  L{p['line_no']:>6}  →  {p['target']:<22} <- {', '.join(p['tags']):<30}  {p['insn']}")

    return "\n".join(lines)
