from __future__ import annotations

"""结构化指令查询和序列搜索。"""

from collections import deque
from fnmatch import fnmatchcase
from pathlib import Path

from .trace_io import RegCondition, TraceLine, iter_lines, _match_reg_condition

def grep(paths: list[str | Path] | str | Path | None = None,
         text: str | None = None,
         pc_range: tuple[int, int] | None = None,
         opcode: str | None = None,
         module: str | None = None,
         reg_filter: dict[str, int] | None = None,
         reg_conditions: list[RegCondition] | None = None,
         max_results: int = 0) -> list[dict]:
    """结构化查询 trace 行。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    results = []
    for tl in iter_lines(paths=paths, text=text):
        # PC 范围过滤
        if pc_range and not (pc_range[0] <= tl.address <= pc_range[1]):
            continue

        # opcode 过滤
        if opcode and opcode not in tl.insn:
            continue

        # module 过滤
        if module and module not in tl.module:
            continue

        # 寄存器值过滤：寄存器在执行前或执行后等于目标值即匹配
        if reg_filter:
            matched = False
            for reg, val in reg_filter.items():
                if reg in tl.regs_before and tl.regs_before[reg] == val:
                    matched = True
                if reg in tl.regs_after and tl.regs_after[reg] == val:
                    matched = True
                # 只有寄存器在两个集合中都不存在时才跳过
            if not matched:
                continue

        if reg_conditions and not all(_match_reg_condition(tl, cond) for cond in reg_conditions):
            continue

        results.append({
            "line_no": tl.line_no,
            "module": tl.module,
            "address": hex(tl.address),
            "offset": hex(tl.offset),
            "insn": tl.insn,
            "raw": tl.raw,
        })

        if max_results and len(results) >= max_results:
            break

    return results


def _normalize_insn_pattern(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _match_insn_pattern(insn: str, pattern: str) -> bool:
    normalized_insn = _normalize_insn_pattern(insn)
    normalized_pattern = _normalize_insn_pattern(pattern)
    return fnmatchcase(normalized_insn, normalized_pattern)


def _trace_line_to_result(tl: TraceLine) -> dict:
    return {
        "line_no": tl.line_no,
        "module": tl.module,
        "address": hex(tl.address),
        "offset": hex(tl.offset),
        "insn": tl.insn,
        "raw": tl.raw,
    }


def search_sequence(
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
    pattern: str = "",
    adjacent: bool = True,
    max_gap: int = 0,
    pc_range: tuple[int, int] | None = None,
    module: str | None = None,
    opcode: str | None = None,
    context: int = 0,
    max_results: int = 0,
) -> list[dict]:
    """按指令序列搜索，pattern 使用分号分隔，支持 * 和 ? wildcard。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    parts = [p.strip() for p in pattern.split(";") if p.strip()]
    if not parts:
        raise ValueError("序列模式不能为空")

    results: list[dict] = []

    def append_result(item: dict) -> bool:
        results.append(item)
        return bool(max_results and len(results) >= max_results)

    context = max(0, context)
    max_gap = max(0, max_gap)
    history: deque[TraceLine] = deque(maxlen=len(parts) + context)
    pending: list[dict] = []
    active: list[dict] = []
    for tl in iter_lines(paths=paths, text=text):
        for item in list(pending):
            if len(item["context_after"]) < context:
                item["context_after"].append(_trace_line_to_result(tl))
            if len(item["context_after"]) >= context:
                pending.remove(item)
                if append_result(item):
                    return results

        if pc_range and not (pc_range[0] <= tl.address <= pc_range[1]):
            history.clear()
            continue
        if module and module not in tl.module:
            history.clear()
            continue

        if not adjacent:
            if max_gap:
                active = [
                    state for state in active
                    if tl.line_no - state["sequence"][-1].line_no - 1 <= max_gap
                ]

            for state in list(active):
                idx = state["next_idx"]
                if idx < len(parts) and _match_insn_pattern(tl.insn, parts[idx]):
                    next_seq = [*state["sequence"], tl]
                    if len(next_seq) == len(parts):
                        if opcode and not any(opcode in item.insn for item in next_seq):
                            continue
                        item = {
                            "start_line": next_seq[0].line_no,
                            "end_line": next_seq[-1].line_no,
                            "count": len(next_seq),
                            "adjacent": False,
                            "context_before": [_trace_line_to_result(item) for item in state["context_before"]],
                            "context_after": [],
                            "sequence": [_trace_line_to_result(item) for item in next_seq],
                        }
                        if context:
                            pending.append(item)
                        else:
                            if append_result(item):
                                return results
                    else:
                        active.append({
                            "sequence": next_seq,
                            "next_idx": idx + 1,
                            "context_before": state["context_before"],
                        })

            if _match_insn_pattern(tl.insn, parts[0]):
                if len(parts) == 1:
                    item = {
                        "start_line": tl.line_no,
                        "end_line": tl.line_no,
                        "count": 1,
                        "adjacent": False,
                        "context_before": [_trace_line_to_result(item) for item in history],
                        "context_after": [],
                        "sequence": [_trace_line_to_result(tl)],
                    }
                    if context:
                        pending.append(item)
                    else:
                        if append_result(item):
                            return results
                else:
                    active.append({
                        "sequence": [tl],
                        "next_idx": 1,
                        "context_before": list(history),
                    })
            if len(active) > 1024:
                active = active[-1024:]
            history.append(tl)
            continue

        history.append(tl)
        if len(history) < len(parts):
            continue
        seq = list(history)[-len(parts):]
        if all(_match_insn_pattern(item.insn, pat) for item, pat in zip(seq, parts)):
            if opcode and not any(opcode in item.insn for item in seq):
                continue
            context_before = list(history)[:max(0, len(history) - len(parts))]
            item = {
                "start_line": seq[0].line_no,
                "end_line": seq[-1].line_no,
                "count": len(seq),
                "adjacent": adjacent,
                "context_before": [_trace_line_to_result(item) for item in context_before],
                "context_after": [],
                "sequence": [_trace_line_to_result(item) for item in seq],
            }
            if context:
                pending.append(item)
            else:
                if append_result(item):
                    break

    if max_results:
        remaining = max(0, max_results - len(results))
        results.extend(pending[:remaining])
    else:
        results.extend(pending)

    return results
