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
        # 尝试找 lz4 并自动解压
        lz4_files = sorted([f for f in runs[0].rglob("*.lz4") if f.is_file()],
                          key=lambda x: x.stat().st_size, reverse=True)
        if lz4_files:
            raise FileNotFoundError(
                f"run 目录只有 .lz4 压缩文件: {runs[0]}\n"
                f"请先解压: lz4 -d {lz4_files[0]}"
            )
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


# ══════════════════════════════════════════════════════════════════
# 9. taint — 污点分析
# ══════════════════════════════════════════════════════════════════

# str/stp 类内存写指令
STORE_OPS = {"str", "stp", "strb", "strh", "stur", "sturb", "sturh"}
# ldr/ldp 类内存读指令
LOAD_OPS = {"ldr", "ldp", "ldrb", "ldrh", "ldur", "ldurb", "ldurh", "ldrsw"}
# ALU 类（结果继承所有源操作数的污点）
ALU_OPS = {"add", "sub", "eor", "and", "orr", "bic", "orn",
           "lsl", "lsr", "asr", "mul", "udiv", "sdiv",
           "csel", "csinc", "csinv", "csneg",
           "mov", "mvn", "neg", "lslv", "lsrv", "asrv"}


# 提取指令中的寄存器操作数
OPERAND_RE = re.compile(r"(?:[xw](\d+)|sp)")


def _extract_regs(insn: str) -> list[str]:
    """从指令中提取所有寄存器名。"""
    regs = []
    parts = insn.replace(",", " ").replace(";", " ").split()
    for p in parts:
        p = p.strip()
        if re.match(r"^[xw](\d+)$", p):
            regs.append(p)
        elif p == "sp":
            regs.append("sp")
    return regs


def _get_mem_addr(insn: str, regs_before: dict[str, int]) -> int | None:
    """从 str/ldr 指令的 [base, #offset] 形式计算绝对地址。"""
    m = re.search(r"\[(x\d+|w\d+|sp)(?:,\s*(#[\-0-9x]+))?\]", insn)
    if not m:
        return None
    base_reg = m.group(1)
    base_val = regs_before.get(base_reg, 0)
    off_str = m.group(2)
    if off_str:
        off_str = off_str.replace("#", "")
        try:
            offset = int(off_str, 16) if "0x" in off_str else int(off_str)
        except ValueError:
            offset = 0
    else:
        offset = 0
    return base_val + offset


# 寄存器别名映射（w0 → x0, w1 → x1 等）
def _reg_canonical(name: str) -> str:
    """统一寄存器名：w0 → x0, 其他不变。"""
    if name.startswith("w") and name[1:].isdigit():
        return f"x{name[1:]}"
    return name


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

    lines = list(iter_lines(paths=paths, text=text))
    if not lines:
        return {"total_instructions": 0, "ret_tainted": False, "ret_tags": [], "propagation_count": 0,
                "propagation": [], "result_register_taint": {}, "result_memory_taint": {}}

    # 污点状态
    reg_taint: dict[str, set[str]] = {}  # 寄存器 → {污点标签}
    mem_taint: dict[int, set[str]] = {}  # 绝对地址 → {污点标签}

    # 初始化污点标记
    if taint_regs:
        for r in taint_regs:
            reg_taint.setdefault(_reg_canonical(r), set()).add(f"input:{r}")

    if taint_mem_range:
        start, end = taint_mem_range
        for addr in range(start, end):
            mem_taint.setdefault(addr, set()).add(f"input:mem_{hex(start)}")

    # 传播链记录
    propagation: list[dict] = []

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
        return mem_taint.get(addr, set()).copy()

    for tl in lines:
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
                # 实际存储的寄存器一般在逗号前（如 stp x29, x30, [sp] → x29, x30）
                all_tags: set[str] = set()
                for sr in store_regs:
                    if sr in regs_before or sr in regs_after:
                        all_tags.update(_get_reg_tags(sr))
                if all_tags:
                    _mark_mem(mem_addr, all_tags, insn, line_no)
            continue

        # ── 内存读: ldr/ldp/ldur → 从内存继承污点 ──
        if op in LOAD_OPS:
            mem_addr = _get_mem_addr(insn, regs_before)
            if mem_addr is not None:
                mem_tags = _get_mem_tags(mem_addr)
                # 目标寄存器（通常是第一个操作数）
                dest_regs = _extract_regs(insn)
                if dest_regs and mem_tags:
                    for dr in [dest_regs[0]]:  # 第一个是目标寄存器
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
            continue

        # ── 比较指令（cmp, cmn）：影响标志位 ──
        if op in {"cmp", "cmn"}:
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

    # 判断返回值（x0）是否被污染
    ret_tainted = "x0" in reg_taint and bool(reg_taint["x0"])

    result = {
        "total_instructions": len(lines),
        "ret_tainted": ret_tainted,
        "ret_tags": list(reg_taint.get("x0", set())) if ret_tainted else [],
        "propagation_count": len(propagation),
        "result_register_taint": final_reg_taint,
        "result_memory_taint": final_mem_taint,
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
    lines.append("")

    if result.get("propagation"):
        lines.append("传播路径 (前 {} 条):".format(min(max_prop, len(result["propagation"]))))
        lines.append("")
        for p in result["propagation"][:max_prop]:
            if p["type"] == "reg":
                arrow = "→" if p["target"] in reg_taint or p["target"].startswith("x") else "→"
                lines.append(f"  L{p['line_no']:>6}  {arrow}  {p['target']:<6}  <- {', '.join(p['tags']):<30}  {p['insn']}")
            else:
                lines.append(f"  L{p['line_no']:>6}  →  {p['target']:<22} <- {', '.join(p['tags']):<30}  {p['insn']}")

    return "\n".join(lines)
