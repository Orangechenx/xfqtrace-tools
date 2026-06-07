from __future__ import annotations

"""
xfq trace 分析引擎 — 8 个只读分析命令的核心逻辑。

trace 日志行格式:
  [module] address!offset instruction; reg_before -> reg_after       # 指令行
  call func: name(x0=..., x1=...)                                     # hook 调用
  ret: value                                                          # 返回值
"""

import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Generator, Iterable


# ── 行解析 ──────────────────────────────────────────────────────

LINE_RE = re.compile(
    r"^\[(?P<module>[^\]]+)\]\s+"           # [module]
    r"(?P<addr>0x[0-9a-f]+)"                # absolute address
    r"!(?P<off>0x[0-9a-f]+)\s+"             # !offset
    r"(?P<insn>.+?)(?:;|$)"                 # instruction (up to ; or end)
)


@dataclass
class TraceLine:
    """解析后的单行 trace。"""
    raw: str
    line_no: int
    module: str = ""
    address: int = 0
    offset: int = 0
    insn: str = ""
    is_instruction: bool = False
    is_call: bool = False
    is_ret: bool = False
    call_name: str = ""
    regs_before: dict[str, int] = field(default_factory=dict)
    regs_after: dict[str, int] = field(default_factory=dict)


def parse_line(line: str, line_no: int = 0) -> TraceLine | None:
    """解析一行 trace 日志，返回 TraceLine 或 None（空行/非 trace 行）。"""
    stripped = line.strip()
    if not stripped:
        return None

    tl = TraceLine(raw=line.rstrip("\n"), line_no=line_no)

    # hook call: call func: name(...)
    if stripped.startswith("call func:"):
        tl.is_call = True
        tl.call_name = stripped[len("call func:"):].strip()
        return tl

    # hook ret: ret: value
    if stripped.startswith("ret:"):
        tl.is_ret = True
        return tl

    # instruction line: [module] addr!offset insn; regs -> regs
    m = LINE_RE.match(stripped)
    if not m:
        return tl

    tl.is_instruction = True
    tl.module = m.group("module")
    tl.address = int(m.group("addr"), 16)
    tl.offset = int(m.group("off"), 16)
    tl.insn = m.group("insn").strip()

    # parse regs after ";"
    if ";" in stripped:
        after_semi = stripped.split(";", 1)[1].strip()
        # split by "->" to get before/after
        if "->" in after_semi:
            before_str, after_str = after_semi.split("->", 1)
        else:
            before_str = after_semi
            after_str = ""
        tl.regs_before = _parse_regs(before_str)
        tl.regs_after = _parse_regs(after_str)

    return tl


REG_RE = re.compile(r"(?P<reg>[xw]\d+|[a-z0-9]+)=(?P<val>0x[0-9a-f]+|\d+)")

def _parse_regs(text: str) -> dict[str, int]:
    """从 'x0=0x1234 x1=0x5678' 提取寄存器字典。"""
    result = {}
    for m in REG_RE.finditer(text):
        name = m.group("reg")
        val_str = m.group("val")
        try:
            val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
        except ValueError:
            continue
        result[name] = val
    return result


# ── 工具函数 ─────────────────────────────────────────────────────

def iter_lines(
    paths: list[str | Path] | None = None,
    text: str | None = None,
    progress: bool = False,
) -> Generator[TraceLine, None, None]:
    """逐行解析 trace 文件。支持 paths 列表或直接传 text。"""
    if text is not None:
        for i, line in enumerate(text.splitlines()):
            tl = parse_line(line, i + 1)
            if tl and tl.is_instruction:
                yield tl
        return

    for p_str in (paths or []):
        p = Path(p_str)
        if not p.exists():
            continue
        total = p.stat().st_size
        reported = 0
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if progress and total > 10_000_000:
                    pct = int(f.tell() * 100 / total)
                    if pct >= reported + 10:
                        reported = (pct // 10) * 10
                        print(f"  [{pct}%]", end=" ", flush=True)
                tl = parse_line(line, i)
                if tl and tl.is_instruction:
                    yield tl


def resolve_trace_file(package: str, log_dir: str | Path | None = None) -> list[Path]:
    """定位指定包的最新 trace 日志文件。"""
    from .config import package_logs_dir, resolve_tool_root

    base = Path(log_dir) if log_dir else package_logs_dir(resolve_tool_root(), package)
    if not base.exists():
        raise FileNotFoundError(f"日志目录不存在: {base}")

    runs = sorted([d for d in base.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True)
    if not runs:
        raise FileNotFoundError(f"日志目录为空: {base}")

    files = sorted([f for f in runs[0].rglob("*") if f.is_file() and not f.name.endswith(".lz4")],
                   key=lambda x: x.stat().st_size, reverse=True)
    if not files:
        raise FileNotFoundError(f"run 目录下无文件: {runs[0]}")

    return files[:1]  # 最大文件


# ══════════════════════════════════════════════════════════════════
# 1. summarize — 算法模式识别
# ══════════════════════════════════════════════════════════════════

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
            if re.match(r"b\.(eq|ne|gt|lt|cs|cc)\s", insn):
                # 尝试解析跳转目标
                m = re.search(r"0x[0-9a-f]+", insn)
                if m and int(m.group(0), 16) <= lines[i].address:
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


def detect_mem_copy(lines: list[TraceLine], window: int = 5) -> list[dict]:
    """检测连续内存拷贝模式（顺序递增地址的写操作）。"""
    results = []
    i = 0
    while i < len(lines) - window:
        chunk = lines[i:i + window]
        writes = [tl for tl in chunk if any(op in tl.insn for op in ["str ", "stp ", "stur "])]
        if len(writes) >= 3:
            # 检查地址是否连续递增
            addrs = []
            for w in writes:
                m = re.search(r"\[(x\d+|w\d+|sp)(?:,\s*(#[\-0-9x]+))?\]", w.insn)
                if not m:
                    break
                reg = f"x{m.group(1)}"
                if reg in w.regs_before:
                    addrs.append(w.regs_before[reg])
                elif reg in w.regs_after:
                    # 当前指令写之前的寄存器值
                    addrs.append(w.regs_after[reg])
                else:
                    break
            if len(addrs) >= 3:
                # 检查是否递增
                diffs = [addrs[k+1] - addrs[k] for k in range(len(addrs)-1)]
                if all(d == diffs[0] for d in diffs):
                    results.append({
                        "type": "sequential_write",
                        "start_line": writes[0].line_no,
                        "end_line": writes[-1].line_no,
                        "stride": diffs[0],
                        "count": len(writes),
                    })
                    i += window
                    continue
        i += 1
    return results


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

    lines = list(iter_lines(paths=paths, text=text))

    patterns = []
    patterns.extend(detect_xor_loop(lines))
    patterns.extend(detect_mem_copy(lines))

    # 统计指令类型
    op_counter: Counter = Counter()
    for tl in lines:
        op = tl.insn.split()[0] if tl.insn else "?"
        op_counter[op] += 1

    top_ops = op_counter.most_common(15)

    return {
        "total_instructions": len(lines),
        "total_lines": len(lines),
        "patterns": patterns,
        "top_opcodes": [{"opcode": op, "count": cnt} for op, cnt in top_ops],
    }


# ══════════════════════════════════════════════════════════════════
# 2. stack — 调用栈可视化
# ══════════════════════════════════════════════════════════════════

CALL_PATTERN = re.compile(r"call\s+(?:func|sub|dlopen|android_dlopen_ext)")
RET_PATTERN = re.compile(r"^\s*ret:")

def build_stack(paths: list[str | Path] | str | Path | None = None,
                text: str | None = None,
                log_dir: str | Path | None = None,
                package: str = "",
                max_depth: int = 20) -> list[dict]:
    """构建调用栈树。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    raw_text = text
    if not raw_text and paths:
        raw_text = paths[0].read_text(encoding="utf-8", errors="replace") if paths[0].stat().st_size > 0 else ""

    if not raw_text or not raw_text.strip():
        return []

    # 扫描调用/返回行（不依赖解析器，处理原始文本更快）
    stack = []
    calls: list[dict] = []
    depth = 0

    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("call func:") or stripped.startswith("call "):
            name = stripped
            if "(" in stripped:
                name = stripped.split("(")[0].replace("call func:", "").replace("call ", "").strip()
            call_info = {"name": name, "depth": depth, "line": stripped}
            calls.append(call_info)
            depth += 1
            if depth > max_depth:
                depth = max_depth
        elif stripped.startswith("ret:"):
            depth = max(0, depth - 1)

    return calls


def format_stack_tree(calls: list[dict], collapse_repeats: bool = True) -> str:
    """格式化调用树为缩进文本。"""
    lines = []
    prev_name = ""
    skip = 0
    for c in calls:
        if collapse_repeats and c["name"] == prev_name:
            skip += 1
            continue
        if skip > 0:
            lines.append("  " * prev_depth + f"  ... x{skip}")
            skip = 0
        indent = "  " * min(c["depth"], 20)
        lines.append(f"{indent}├─ {c['name']}")
        prev_name = c["name"]
        prev_depth = c["depth"]

    if skip > 0:
        lines.append("  " * prev_depth + f"  ... x{skip}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# 3. grep — 结构化查询
# ══════════════════════════════════════════════════════════════════

def grep(paths: list[str | Path] | str | Path | None = None,
         text: str | None = None,
         pc_range: tuple[int, int] | None = None,
         opcode: str | None = None,
         module: str | None = None,
         reg_filter: dict[str, int] | None = None,
         max_results: int = 0) -> list[dict]:
    """结构化查询 trace 行。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    lines = list(iter_lines(paths=paths, text=text))

    results = []
    for tl in lines:
        # PC 范围过滤
        if pc_range and not (pc_range[0] <= tl.address <= pc_range[1]):
            continue

        # opcode 过滤
        if opcode and opcode not in tl.insn:
            continue

        # module 过滤
        if module and module not in tl.module:
            continue

        # 寄存器值过滤
        if reg_filter:
            matched = True
            for reg, val in reg_filter.items():
                if reg in tl.regs_before and tl.regs_before[reg] != val:
                    matched = False
                    break
                if reg in tl.regs_after and tl.regs_after[reg] != val:
                    matched = False
                    break
            if not matched:
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


# ══════════════════════════════════════════════════════════════════
# 4. slice — 切片导出
# ══════════════════════════════════════════════════════════════════

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

    with path.open("r", encoding="utf-8", errors="replace") as fin:
        with out_path.open("w", encoding="utf-8") as fout:
            for i, line in enumerate(fin, 1):
                total += 1

                # 行号范围
                if line_range and not (line_range[0] <= i <= line_range[1]):
                    continue

                # PC 范围
                if pc_range:
                    m = re.search(r"0x[0-9a-f]+", line)
                    if m:
                        addr = int(m.group(0), 16)
                        if not (pc_range[0] <= addr <= pc_range[1]):
                            skipped += 1
                            continue
                    else:
                        skipped += 1
                        continue

                fout.write(line)
                written += 1
                if max_lines and written >= max_lines:
                    break

    return {
        "input": str(path),
        "output": str(out_path),
        "input_size": path.stat().st_size,
        "total_lines": total,
        "written_lines": written,
        "skipped_lines": skipped,
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

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    raw_text = text
    if not raw_text and paths:
        raw_text = paths[0].read_text(encoding="utf-8", errors="replace") if paths[0].stat().st_size > 0 else ""

    if not raw_text or not raw_text.strip():
        return {
            "total_instructions": 0,
            "total_calls": 0,
            "calls": [],
            "top_opcodes": [],
        }

    # 直接从文本解析更快
    call_counter: Counter = Counter()
    op_counter: Counter = Counter()
    total_instructions = 0
    total_calls = 0

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # 检查是否是 hook call
        if stripped.startswith("call "):
            total_calls += 1
            name = stripped
            if "(" in stripped:
                name = stripped.split("(")[0]
            name = name.replace("call func:", "").replace("call sub ", "sub_").replace("call dlopen", "dlopen").strip()
            call_counter[name] += 1

        # 检查是否是指令行
        elif stripped.startswith("["):
            total_instructions += 1
            m = re.search(r"!\S+\s+(.+?)(?:;|$)", stripped)
            if m:
                insn = m.group(1).strip()
                op = insn.split()[0] if insn else "?"
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

    lines = list(iter_lines(paths=paths, text=text))

    change_count: Counter = Counter()
    first_val: dict[str, int] = {}
    last_val: dict[str, int] = {}
    min_val: dict[str, int] = {}
    max_val: dict[str, int] = {}
    observed: set[str] = set()

    for tl in lines:
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

    results.sort(key=lambda x: x["changes"], reverse=True)
    return results


# ══════════════════════════════════════════════════════════════════
# 7. mempat — 内存访问模式检测
# ══════════════════════════════════════════════════════════════════

def mempat(paths: list[str | Path] | str | Path | None = None,
           text: str | None = None,
           log_dir: str | Path | None = None,
           package: str = "") -> list[dict]:
    """检测连续内存操作模式（memset/memcpy）。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    lines = list(iter_lines(paths=paths, text=text))

    patterns = []
    i = 0
    while i < len(lines):
        tl = lines[i]
        insn = tl.insn

        # 只看内存写指令
        if not any(op in insn for op in ["str ", "stp ", "stur "]):
            i += 1
            continue

        # 看连续几条是否地址递增
        seq = []
        for j in range(i, min(i + 20, len(lines))):
            tj = lines[j]
            ij = tj.insn
            if not any(op in ij for op in ["str ", "stp ", "stur "]):
                break
            mj = re.search(r"\[(x\d+|w\d+|sp)(?:,\s*(#[\-0-9x]+))?\]", ij)
            if not mj:
                break
            bj = tj.regs_before.get(mj.group(1), 0)
            try:
                oj_str = mj.group(2) or "#0"
                oj = int(oj_str.replace("#", ""), 16) if "0x" in oj_str else int(oj_str.replace("#", ""))
            except (ValueError, AttributeError):
                oj = 0
            seq.append({"base": bj, "offset": oj, "line_no": tj.line_no, "idx": j})

        if len(seq) >= 3:
            # 检查地址是否连续递增
            addrs = [s["base"] + s["offset"] for s in seq]
            diffs = [addrs[k+1] - addrs[k] for k in range(len(addrs)-1)]
            if all(d == diffs[0] for d in diffs):
                patterns.append({
                    "type": "sequential_write",
                    "start_line": seq[0]["line_no"],
                    "end_line": seq[-1]["line_no"],
                    "stride": diffs[0],
                    "count": len(seq),
                })
                i = seq[-1]["idx"] + 1  # 跳过整个连续的块
                continue

        i += 1

    return patterns


# ══════════════════════════════════════════════════════════════════
# 8. branch — 分支命中率分析
# ══════════════════════════════════════════════════════════════════

# 条件跳转指令前缀
COND_BRANCHES = {"b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl",
                 "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt",
                 "b.gt", "b.le", "b.al", "cbnz", "cbz", "tbnz", "tbz"}


def branch_analysis(paths: list[str | Path] | str | Path | None = None,
                    text: str | None = None,
                    log_dir: str | Path | None = None,
                    package: str = "") -> list[dict]:
    """分析条件分支跳转率。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    lines = list(iter_lines(paths=paths, text=text))

    branches: dict[str, dict] = {}

    for i, tl in enumerate(lines):
        insn = tl.insn
        op = insn.split()[0] if insn else ""

        if op not in COND_BRANCHES:
            continue

        # 提取跳转目标
        m = re.search(r"(?:0x[0-9a-f]+)", insn)
        target_str = m.group(0) if m else ""

        # 看下一条指令地址
        next_addr = lines[i + 1].address if i + 1 < len(lines) else 0

        # 是否跳转
        key = f"{tl.module}:{hex(tl.offset)} {insn}"
        if key not in branches:
            branches[key] = {
                "module": tl.module,
                "offset": hex(tl.offset),
                "insn": insn,
                "target": target_str,
                "taken": 0,
                "not_taken": 0,
            }

        if target_str and next_addr:
            target_addr = int(target_str, 16)
            if target_addr == next_addr:
                # 条件为假，没跳转
                branches[key]["not_taken"] += 1
            else:
                branches[key]["taken"] += 1

    results = []
    for key, info in branches.items():
        total = info["taken"] + info["not_taken"]
        rate = (info["taken"] / total * 100) if total > 0 else 0
        results.append({
            "module": info["module"],
            "offset": info["offset"],
            "insn": info["insn"],
            "target": info["target"],
            "taken": info["taken"],
            "not_taken": info["not_taken"],
            "taken_ratio": round(rate, 1),
            "total": total,
        })

    results.sort(key=lambda x: x["total"], reverse=True)
    return results
