from __future__ import annotations

"""算法摘要和内存访问模式检测。"""

import re
from collections import Counter, deque
from pathlib import Path
from typing import Generator

from .trace_branch import COND_BRANCHES
from .trace_io import TraceLine, iter_lines, resolve_trace_file, _trace_size_warnings
from .trace_memory import LOAD_OPS, STORE_OPS, _get_mem_addr

def detect_xor_loop(lines: list[TraceLine]) -> list[dict]:
    """检测连续 eor + 分支回跳 → XOR 循环。"""
    results = []
    i = 0
    while i < len(lines) - 2:
        # 找 eor 指令
        if "eor" not in lines[i].insn:
            i += 1
            continue
        # 看后面是否有条件跳转回前面
        for j in range(i + 1, min(i + 10, len(lines))):
            insn = lines[j].insn
            op_j = insn.split()[0] if insn else ""
            # 条件跳转（b.cond, cbz, cbnz, tbnz, tbz）
            if op_j in COND_BRANCHES or re.match(r"b\.(eq|ne|gt|lt|cs|cc|mi|pl|vs|vc|hi|ls|ge|le|al)\b", insn):
                # 判断是否为向后跳转（循环）：负偏移或回跳
                is_backward = False
                if "#-" in insn:
                    is_backward = True  # 负偏移 → 回跳
                else:
                    # 取最后一个 0x 值作为跳转偏移
                    hex_vals = re.findall(r"[-]?0x[0-9a-f]+", insn)
                    if hex_vals:
                        # 尝试从偏移和当前地址判断方向
                        try:
                            offset = int(hex_vals[-1], 16)
                            target_addr = lines[j].address + offset  # 近似：正偏移 = forward
                            if target_addr <= lines[i].address:
                                is_backward = True
                        except (ValueError, IndexError):
                            pass

                if is_backward:
                    results.append({
                        "type": "xor_loop",
                        "start_line": lines[i].line_no,
                        "end_line": lines[j].line_no,
                        "eor_insn": lines[i].insn,
                        "branch": insn,
                    })
                    i = j
                    break
        i += 1
    return results


def _insn_op(insn: str) -> str:
    """提取 opcode，空指令返回空字符串。"""
    return insn.split()[0] if insn else ""


def detect_sequential_access(
    lines: list[TraceLine],
    ops: set[str],
    mode: str,
    window: int = 20,
    min_count: int = 3,
) -> list[dict]:
    """检测相邻内存访问指令是否按固定 stride 访问地址。"""
    results = []
    i = 0
    while i < len(lines):
        if _insn_op(lines[i].insn) not in ops:
            i += 1
            continue

        seq: list[tuple[TraceLine, int, int]] = []
        for j in range(i, min(i + window, len(lines))):
            tl = lines[j]
            if _insn_op(tl.insn) not in ops:
                break
            addr = _get_mem_addr(tl.insn, tl.regs_before)
            if addr is None:
                break
            seq.append((tl, addr, j))

        if len(seq) >= min_count:
            addrs = [addr for _, addr, _ in seq]
            diffs = [addrs[k + 1] - addrs[k] for k in range(len(addrs) - 1)]
            if diffs and all(d == diffs[0] for d in diffs):
                results.append({
                    "type": f"sequential_{mode}",
                    "start_line": seq[0][0].line_no,
                    "end_line": seq[-1][0].line_no,
                    "stride": diffs[0],
                    "count": len(seq),
                })
                i = seq[-1][2] + 1
                continue
        i += 1
    return results


def detect_mem_copy(lines: list[TraceLine], window: int = 5) -> list[dict]:
    """检测连续内存拷贝模式（顺序递增地址的写操作）。"""
    return detect_sequential_access(lines, STORE_OPS, mode="write", window=window)


def _is_conditional_branch(insn: str) -> bool:
    op = _insn_op(insn)
    return op in COND_BRANCHES or bool(re.match(r"b\.(eq|ne|gt|lt|cs|cc|mi|pl|vs|vc|hi|ls|ge|le|al)\b", insn))


def _is_backward_branch(branch: TraceLine, start: TraceLine) -> bool:
    if "#-" in branch.insn:
        return True
    hex_vals = re.findall(r"-?0[xX][0-9a-fA-F]+", branch.insn)
    if not hex_vals:
        return False
    try:
        offset = int(hex_vals[-1], 0)
    except ValueError:
        return False
    return branch.address + offset <= start.address


def detect_xor_loop_stream(lines: Generator[TraceLine, None, None]) -> tuple[list[dict], Counter, int]:
    """流式检测 XOR 循环，同时统计 opcode。"""
    patterns: list[dict] = []
    op_counter: Counter = Counter()
    total = 0
    pending_eors: deque[tuple[TraceLine, int]] = deque()

    for tl in lines:
        total += 1
        op = _insn_op(tl.insn) or "?"
        op_counter[op] += 1

        if pending_eors and _is_conditional_branch(tl.insn):
            kept: deque[tuple[TraceLine, int]] = deque()
            for eor_line, remaining in pending_eors:
                if _is_backward_branch(tl, eor_line):
                    patterns.append({
                        "type": "xor_loop",
                        "start_line": eor_line.line_no,
                        "end_line": tl.line_no,
                        "eor_insn": eor_line.insn,
                        "branch": tl.insn,
                    })
                    continue
                if remaining > 1:
                    kept.append((eor_line, remaining - 1))
            pending_eors = kept
        else:
            pending_eors = deque(
                (eor_line, remaining - 1)
                for eor_line, remaining in pending_eors
                if remaining > 1
            )

        if "eor" in tl.insn:
            pending_eors.append((tl, 10))

    return patterns, op_counter, total


def summarize(paths: list[str | Path] | str | Path | None = None,
              text: str | None = None,
              log_dir: str | Path | None = None,
              package: str = "") -> dict:
    """智能摘要：识别算法模式。"""
    # 收集行
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    if not paths and text is None:
        raise ValueError("必须提供 paths、text 或 package")

    warnings = _trace_size_warnings(paths, "summarize", 2)
    patterns, op_counter, total = detect_xor_loop_stream(iter_lines(paths=paths, text=text))
    patterns.extend(p for p in mempat(paths=paths, text=text) if p["type"] == "sequential_write")

    top_ops = op_counter.most_common(15)

    return {
        "total_instructions": total,
        "total_lines": total,
        "patterns": patterns,
        "top_opcodes": [{"opcode": op, "count": cnt} for op, cnt in top_ops],
        "streaming": True,
        "analysis_passes": 2,
        "warnings": warnings,
    }

def _flush_mem_sequence(
    patterns: list[dict],
    seq: list[tuple[TraceLine, int]],
    mode: str,
    min_count: int = 3,
) -> None:
    if len(seq) < min_count:
        return
    addrs = [addr for _, addr in seq]
    diffs = [addrs[k + 1] - addrs[k] for k in range(len(addrs) - 1)]
    if diffs and all(d == diffs[0] for d in diffs):
        patterns.append({
            "type": f"sequential_{mode}",
            "start_line": seq[0][0].line_no,
            "end_line": seq[-1][0].line_no,
            "stride": diffs[0],
            "count": len(seq),
        })


def detect_memory_access_patterns_stream(
    lines: Generator[TraceLine, None, None],
    window: int = 20,
    min_count: int = 3,
) -> list[dict]:
    """流式检测连续内存读写，避免为大 trace 保留全部指令。"""
    patterns: list[dict] = []
    seq: list[tuple[TraceLine, int]] = []
    seq_mode = ""

    for tl in lines:
        op = _insn_op(tl.insn)
        mode = "write" if op in STORE_OPS else "read" if op in LOAD_OPS else ""
        addr = _get_mem_addr(tl.insn, tl.regs_before) if mode else None
        if not mode or addr is None:
            _flush_mem_sequence(patterns, seq, seq_mode, min_count=min_count)
            seq = []
            seq_mode = ""
            continue

        if seq_mode and mode != seq_mode:
            _flush_mem_sequence(patterns, seq, seq_mode, min_count=min_count)
            seq = []
        seq_mode = mode
        seq.append((tl, addr))

        if len(seq) >= window:
            _flush_mem_sequence(patterns, seq, seq_mode, min_count=min_count)
            seq = []
            seq_mode = ""

    _flush_mem_sequence(patterns, seq, seq_mode, min_count=min_count)
    patterns.sort(key=lambda p: (p["start_line"], p["type"]))
    return patterns


def mempat(paths: list[str | Path] | str | Path | None = None,
           text: str | None = None,
           log_dir: str | Path | None = None,
           package: str = "") -> list[dict]:
    """检测连续内存操作模式（memset/memcpy）。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    return detect_memory_access_patterns_stream(iter_lines(paths=paths, text=text), window=20)
