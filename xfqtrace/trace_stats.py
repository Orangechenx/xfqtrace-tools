from __future__ import annotations

"""trace 切片、调用统计和寄存器变化统计。"""

import re
from collections import Counter
from pathlib import Path

from .trace_io import iter_lines, iter_raw_lines, parse_line, resolve_trace_file
from .trace_stack import _normalize_call_name

def slice_trace(path: str | Path,
                output: str | Path,
                pc_range: tuple[int, int] | None = None,
                line_range: tuple[int, int] | None = None,
                max_lines: int = 0) -> dict:
    """从原始 trace 文件裁剪出指定范围的指令子集。"""
    path = Path(path)
    out_path = Path(output)

    total = 0
    written = 0
    skipped = 0
    truncated = False
    total_lines_exact = True

    raw_iter = iter_raw_lines(paths=[path])
    with out_path.open("w", encoding="utf-8") as fout:
        for i, line in raw_iter:
            total += 1

            # 行号范围
            if line_range and not (line_range[0] <= i <= line_range[1]):
                continue

            # PC 范围
            if pc_range:
                m = re.search(r"0[xX][0-9a-fA-F]+", line)
                if m:
                    addr = int(m.group(0), 16)
                    if not (pc_range[0] <= addr <= pc_range[1]):
                        skipped += 1
                        continue
                else:
                    skipped += 1
                    continue

            fout.write(line if line.endswith("\n") else f"{line}\n")
            written += 1
            if max_lines and written >= max_lines:
                truncated = True
                total_lines_exact = False
                break

    return {
        "input": str(path),
        "output": str(out_path),
        "input_size": path.stat().st_size,
        "total_lines": total,
        "total_lines_exact": total_lines_exact,
        "written_lines": written,
        "skipped_lines": skipped,
        "truncated": truncated,
    }


# ══════════════════════════════════════════════════════════════════
# 5. stats — API 调用统计
# ══════════════════════════════════════════════════════════════════

def stats(paths: list[str | Path] | str | Path | None = None,
          text: str | None = None,
          log_dir: str | Path | None = None,
          package: str = "") -> dict:
    """统计 trace 中的调用/指令信息。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]
    elif paths:
        paths = [Path(p) if isinstance(p, str) else p for p in paths]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    call_counter: Counter = Counter()
    op_counter: Counter = Counter()
    total_instructions = 0
    total_calls = 0

    for _, line in iter_raw_lines(paths=paths, text=text):
        stripped = line.strip()
        if not stripped:
            continue

        # 检查是否是 xfQTrace 已知 hook call
        call_name = _normalize_call_name(stripped)
        if call_name is not None:
            total_calls += 1
            call_counter[call_name] += 1

        # 检查是否是指令行
        elif stripped.startswith("["):
            tl = parse_line(stripped)
            if tl and tl.is_instruction:
                total_instructions += 1
                op = tl.insn.split()[0] if tl.insn else "?"
                op_counter[op] += 1

    return {
        "total_instructions": total_instructions,
        "total_calls": total_calls,
        "calls": [{"name": name, "count": cnt} for name, cnt in call_counter.most_common(30)],
        "top_opcodes": [{"opcode": op, "count": cnt} for op, cnt in op_counter.most_common(20)],
    }


# ══════════════════════════════════════════════════════════════════
# 6. regdiff — 寄存器变化热力图
# ══════════════════════════════════════════════════════════════════

def regdiff(paths: list[str | Path] | str | Path | None = None,
            text: str | None = None,
            log_dir: str | Path | None = None,
            package: str = "",
            target_regs: list[str] | None = None) -> list[dict]:
    """寄存器变化统计。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    change_count: Counter = Counter()
    first_val: dict[str, int] = {}
    last_val: dict[str, int] = {}
    min_val: dict[str, int] = {}
    max_val: dict[str, int] = {}
    observed: set[str] = set()

    for tl in iter_lines(paths=paths, text=text):
        for reg, val in tl.regs_after.items():
            if target_regs and reg not in target_regs:
                continue
            observed.add(reg)
            if reg not in first_val:
                first_val[reg] = val
            last_val[reg] = val
            min_val[reg] = min(min_val.get(reg, val), val)
            max_val[reg] = max(max_val.get(reg, val), val)
            if reg in tl.regs_before and tl.regs_before[reg] != val:
                change_count[reg] += 1

    results = []
    for reg in observed:
        results.append({
            "register": reg,
            "changes": change_count.get(reg, 0),
            "first": hex(first_val.get(reg, 0)),
            "last": hex(last_val.get(reg, 0)),
            "min": hex(min_val.get(reg, 0)),
            "max": hex(max_val.get(reg, 0)),
        })

    results.sort(key=lambda x: (-x["changes"], x["register"]))
    return results
