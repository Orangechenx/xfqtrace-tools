from __future__ import annotations

"""条件分支和间接跳转统计。"""

import re
from pathlib import Path

from .trace_io import TraceLine, iter_lines, resolve_trace_file

COND_BRANCHES = {"b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl",
                 "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt",
                 "b.gt", "b.le", "b.al", "cbnz", "cbz", "tbnz", "tbz"}
INDIRECT_BRANCHES = {"br", "blr"}


def _infer_instruction_step(tl: TraceLine) -> tuple[int, str, list[str]]:
    """从 trace 标记或地址低位推断 fallthrough 步长。"""
    raw = tl.raw.lower()
    module = tl.module.lower()
    if "thumb" in raw or "thumb" in module or (tl.address & 1):
        return 2, "thumb_inferred_2_bytes", [
            "Thumb 指令长度根据 trace 标记或奇数地址推断；16/32 位 Thumb 混合场景仍可能需要人工校验。"
        ]
    return 4, "aarch64_fixed_4_bytes", [
        "未发现指令集状态标记，fallthrough 按 AArch64 固定 4 字节推断。"
    ]


def _parse_branch_target(insn: str, current_addr: int) -> int | None:
    """解析分支目标；带 # 的立即数按相对偏移处理。"""
    relative_matches = list(re.finditer(r"#(?P<delta>-?0[xX][0-9a-fA-F]+|-?\d+)", insn))
    if relative_matches:
        try:
            return (current_addr & ~1) + int(relative_matches[-1].group("delta"), 0)
        except ValueError:
            return None

    m_target = re.search(r"(0[xX][0-9a-fA-F]+)", insn)
    if not m_target:
        return None
    try:
        return int(m_target.group(0), 16)
    except ValueError:
        return None


def _same_trace_addr(left: int, right: int) -> bool:
    """忽略 Thumb 状态位比较 trace 地址。"""
    return (left & ~1) == (right & ~1)


def _append_warning(info: dict, warning: str) -> None:
    warnings = info.setdefault("warnings", [])
    if warning not in warnings:
        warnings.append(warning)


def branch_analysis(paths: list[str | Path] | str | Path | None = None,
                    text: str | None = None,
                    log_dir: str | Path | None = None,
                    package: str = "") -> list[dict]:
    """分析条件分支跳转率。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    branches: dict[str, dict] = {}
    pending_conditional: TraceLine | None = None

    for tl in iter_lines(paths=paths, text=text):
        if pending_conditional is not None:
            pending = pending_conditional
            pending_insn = pending.insn
            key = f"{pending.module}:{hex(pending.offset)} {pending_insn}"
            instruction_size, _, _ = _infer_instruction_step(pending)
            fallthrough_addr = (pending.address & ~1) + instruction_size
            target_addr = branches[key].get("target_address")
            if _same_trace_addr(tl.address, fallthrough_addr):
                branches[key]["not_taken"] += 1
            elif target_addr is not None and _same_trace_addr(tl.address, target_addr):
                branches[key]["taken"] += 1
            else:
                branches[key]["unknown"] += 1
                _append_warning(
                    branches[key],
                    "下一条 trace 指令既不是 fallthrough 也不是显式 target，可能存在 trace 间隙/中断/信号，已计入 unknown。",
                )
            pending_conditional = None

        insn = tl.insn
        op = insn.split()[0] if insn else ""

        if op in INDIRECT_BRANCHES:
            key = f"{tl.module}:{hex(tl.offset)} {insn}"
            if key not in branches:
                instruction_size, arch_assumption, warnings = _infer_instruction_step(tl)
                branches[key] = {
                    "type": "indirect",
                    "arch_assumption": arch_assumption,
                    "instruction_size": instruction_size,
                    "module": tl.module,
                    "offset": hex(tl.offset),
                    "insn": insn,
                    "target": insn.split(None, 1)[1] if len(insn.split(None, 1)) == 2 else "",
                    "taken": 0,
                    "not_taken": 0,
                    "count": 0,
                    "warnings": warnings,
                }
            branches[key]["count"] += 1
            continue

        if op not in COND_BRANCHES:
            continue

        # 提取跳转目标（可能是绝对地址或偏移）
        target_addr = _parse_branch_target(insn, tl.address)
        target_str = hex(target_addr) if target_addr is not None else ""

        key = f"{tl.module}:{hex(tl.offset)} {insn}"
        if key not in branches:
            instruction_size, arch_assumption, warnings = _infer_instruction_step(tl)
            branches[key] = {
                "type": "conditional",
                "arch_assumption": arch_assumption,
                "instruction_size": instruction_size,
                "module": tl.module,
                "offset": hex(tl.offset),
                "insn": insn,
                "target": target_str,
                "target_address": target_addr,
                "taken": 0,
                "not_taken": 0,
                "unknown": 0,
                "warnings": warnings,
            }

        pending_conditional = tl

    if pending_conditional is not None:
        key = f"{pending_conditional.module}:{hex(pending_conditional.offset)} {pending_conditional.insn}"
        branches[key]["unknown"] += 1
        _append_warning(
            branches[key],
            "条件分支后没有下一条 trace 指令，无法判断 taken/not_taken，已计入 unknown。",
        )

    results = []
    for key, info in branches.items():
        if info.get("type") == "indirect":
            results.append({
                "type": "indirect",
                "arch_assumption": info["arch_assumption"],
                "instruction_size": info["instruction_size"],
                "module": info["module"],
                "offset": info["offset"],
                "insn": info["insn"],
                "target": info["target"],
                "taken": 0,
                "not_taken": 0,
                "unknown": 0,
                "taken_ratio": 0,
                "total": info["count"],
                "warnings": info.get("warnings", []),
            })
            continue

        known_total = info["taken"] + info["not_taken"]
        total = known_total + info.get("unknown", 0)
        rate = (info["taken"] / known_total * 100) if known_total > 0 else 0
        results.append({
            "type": "conditional",
            "arch_assumption": info["arch_assumption"],
            "instruction_size": info["instruction_size"],
            "module": info["module"],
            "offset": info["offset"],
            "insn": info["insn"],
            "target": info["target"],
            "taken": info["taken"],
            "not_taken": info["not_taken"],
            "unknown": info.get("unknown", 0),
            "taken_ratio": round(rate, 1),
            "total": total,
            "warnings": info.get("warnings", []),
        })

    results.sort(key=lambda x: (-x["total"], x["offset"], x["insn"]))
    return results
