from __future__ import annotations

"""轻量污点传播分析。"""

from pathlib import Path

from .trace_io import iter_lines, resolve_trace_file, _reg_canonical
from .trace_memory import LOAD_OPS, STORE_OPS, _extract_regs, _get_mem_addr

ALU_OPS = {"add", "sub", "eor", "and", "orr", "bic", "orn",
           "lsl", "lsr", "asr", "mul", "udiv", "sdiv",
           "csel", "csinc", "csinv", "csneg", "cset",
           "madd", "msub", "smull", "umull", "smulh", "umulh",
           "movk", "adrp",
           "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw",
           "mov", "mvn", "neg", "lslv", "lsrv", "asrv", "ror", "rorv"}


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
    mem_taint: dict[int, set[str]] = {}  # 绝对地址 → {污点标签}
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

    def _mark_reg(reg: str, tags: set[str], source_insn: str, line_no: int) -> None:
        """标记寄存器并记录传播链。"""
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

    def _get_reg_tags(reg: str) -> set[str]:
        return reg_taint.get(_reg_canonical(reg), set()).copy()

    def _get_mem_tags(addr: int) -> set[str]:
        tags = mem_taint.get(addr, set()).copy()
        for start, end, range_tags in initial_mem_ranges:
            if start <= addr < end:
                tags.update(range_tags)
        return tags

    for tl in iter_lines(paths=paths, text=text):
        total_instructions += 1
        insn = tl.insn.strip()
        op = insn.split()[0] if insn else ""
        regs_before = tl.regs_before
        regs_after = tl.regs_after
        line_no = tl.line_no

        if not op:
            continue

        # ── 内存写: str/stp/stur → 标记目标内存 ──
        if op in STORE_OPS:
            # 提取写入的寄存器和目标地址
            mem_addr = _get_mem_addr(insn, regs_before)
            if mem_addr is not None:
                # 收集源寄存器的污点
                store_regs = _extract_regs(insn.split("]")[0] if "]" in insn else insn)
                if op == "stp" and len(store_regs) >= 2:
                    # STP: 每个寄存器单独标记对应地址
                    tags_0 = _get_reg_tags(store_regs[0])
                    tags_1 = _get_reg_tags(store_regs[1])
                    if tags_0:
                        _mark_mem(mem_addr, tags_0, insn, line_no)
                    if tags_1:
                        _mark_mem(mem_addr + 8, tags_1, insn, line_no)
                else:
                    # STR/STUR/STRB: 收集源寄存器的污点
                    all_tags: set[str] = set()
                    for sr in store_regs:
                        canon = _reg_canonical(sr)
                        if sr in regs_before or sr in regs_after or canon in regs_before or canon in regs_after:
                            all_tags.update(_get_reg_tags(sr))
                    if all_tags:
                        _mark_mem(mem_addr, all_tags, insn, line_no)
            continue

        # ── 内存读: ldr/ldp/ldur → 从内存继承污点 ──
        if op in LOAD_OPS:
            mem_addr = _get_mem_addr(insn, regs_before)
            if mem_addr is not None:
                dest_regs = _extract_regs(insn)
                if op == "ldp" and len(dest_regs) >= 2:
                    # LDP: 每个目标寄存器继承对应地址的污点
                    tags_0 = _get_mem_tags(mem_addr)
                    tags_1 = _get_mem_tags(mem_addr + 8)
                    if tags_0:
                        _mark_reg(dest_regs[0], tags_0, insn, line_no)
                    if tags_1:
                        _mark_reg(dest_regs[1], tags_1, insn, line_no)
                elif dest_regs:
                    mem_tags = _get_mem_tags(mem_addr)
                    if mem_tags:
                        for dr in dest_regs:
                            _mark_reg(dr, mem_tags, insn, line_no)
            continue

        # ── ALU / mov: 结果继承所有源寄存器的污点 ──
        if op in ALU_OPS:
            all_regs = _extract_regs(insn)
            if len(all_regs) >= 2:
                dest = all_regs[0]  # 第一个是目标
                src_regs = all_regs[1:]
                all_src_tags: set[str] = set()
                for sr in src_regs:
                    # 检查该寄存器在执行前/后是否有值
                    if sr in regs_before or sr in regs_after:
                        all_src_tags.update(_get_reg_tags(sr))
                    # 检查 w/x 别名
                    alt = _reg_canonical(sr)
                    if alt != sr:
                        all_src_tags.update(_get_reg_tags(alt))
                if all_src_tags:
                    _mark_reg(dest, all_src_tags, insn, line_no)
            elif op in {"movk", "cset"} and all_regs:
                # movk/cset：读取并修改目标寄存器，保留已有污点
                # cset 还读取 nzcv 标志位
                dest = all_regs[0]
                existing = _get_reg_tags(dest)
                existing.update(_get_reg_tags("nzcv"))
                if existing:
                    _mark_reg(dest, existing, insn, line_no)
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
    final_mem_taint = {hex(addr): list(tags) for addr, tags in mem_taint.items() if tags}
    final_mem_ranges = [
        {"start": hex(start), "end": hex(end), "tags": list(tags)}
        for start, end, tags in initial_mem_ranges
        if tags
    ]

    # 判断返回值（x0）是否被污染
    ret_tainted = "x0" in reg_taint and bool(reg_taint["x0"])

    result = {
        "total_instructions": total_instructions,
        "ret_tainted": ret_tainted,
        "ret_tags": list(reg_taint.get("x0", set())) if ret_tainted else [],
        "propagation_count": len(propagation),
        "taint_granularity": "address_level",
        "result_register_taint": final_reg_taint,
        "result_memory_taint": final_mem_taint,
        "result_memory_taint_ranges": final_mem_ranges,
        "warnings": [
            "内存污点按地址标签记录，不跟踪访问宽度；strb/strh 等部分写和 stp 跨宽度写入为保守近似。"
        ],
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
    lines.append(f"  污染寄存器: {len(result['result_register_taint'])} 个")
    lines.append(f"  污染内存: {len(result['result_memory_taint'])} 处")
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
