from __future__ import annotations

"""trace 行解析、文件读取和日志定位。"""

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

from . import config as cfg

LARGE_TRACE_WARNING_BYTES = 500 * 1024 * 1024


# ── 行解析 ──────────────────────────────────────────────────────

LINE_RE = re.compile(
    r"^\[\s*(?P<module>[^\]]+?)\s*\]\s+"    # [ module ]
    r"(?P<addr>0[xX][0-9a-fA-F]+)"          # absolute address
    r"!(?P<off>0[xX][0-9a-fA-F]+)\s+"       # !offset
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


@dataclass(frozen=True)
class RegCondition:
    """寄存器值过滤条件。"""
    reg: str
    op: str
    value: int
    end: int | None = None


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
    tl.module = m.group("module").strip()
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


REG_RE = re.compile(r"(?P<reg>[xw]\d+|[a-z0-9]+)=(?P<val>-?0[xX][0-9a-fA-F]+|-?\d+)")


def _parse_int_literal(value: str | None) -> int | None:
    """解析 trace 中的十进制/十六进制整数，失败时返回 None。"""
    if value is None:
        return None
    raw = value.strip().replace("#", "")
    if not raw:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return None


def _parse_regs(text: str) -> dict[str, int]:
    """从 'x0=0x1234 x1=0x5678' 提取寄存器字典。"""
    result = {}
    for m in REG_RE.finditer(text):
        name = m.group("reg")
        val = _parse_int_literal(m.group("val"))
        if val is None:
            continue
        result[name] = val
    return result


def parse_reg_condition(expr: str) -> RegCondition:
    """解析寄存器条件，支持 =/!=/>/>=/</<= 和 reg:start-end。"""
    raw = expr.strip()
    range_m = re.match(
        r"^(?P<reg>[xw]\d+|sp|[a-z0-9]+)\s*:\s*(?P<start>-?(?:0[xX][0-9a-fA-F]+|\d+))\s*-\s*(?P<end>-?(?:0[xX][0-9a-fA-F]+|\d+))$",
        raw,
    )
    if range_m:
        start = _parse_int_literal(range_m.group("start"))
        end = _parse_int_literal(range_m.group("end"))
        if start is None or end is None:
            raise ValueError(f"寄存器范围格式错误: {expr}")
        if start > end:
            raise ValueError(f"寄存器范围起始值不能大于结束值: {expr}")
        return RegCondition(range_m.group("reg"), "range", start, end)

    m = re.match(
        r"^(?P<reg>[xw]\d+|sp|[a-z0-9]+)\s*(?P<op>>=|<=|!=|=|>|<)\s*(?P<value>-?(?:0[xX][0-9a-fA-F]+|\d+))$",
        raw,
    )
    if not m:
        raise ValueError(f"寄存器条件格式错误，应为 x0=0x1234 / x0>=0x100 / x0:0x100-0x200: {expr}")
    value = _parse_int_literal(m.group("value"))
    if value is None:
        raise ValueError(f"寄存器值格式错误: {expr}")
    return RegCondition(m.group("reg"), m.group("op"), value)


def _reg_values_for_condition(tl: TraceLine, reg: str) -> list[int]:
    values = []
    for regs in (tl.regs_before, tl.regs_after):
        if reg in regs:
            values.append(regs[reg])
        canon = _reg_canonical(reg)
        if canon != reg and canon in regs:
            values.append(regs[canon])
        elif canon.startswith("x"):
            alt = f"w{canon[1:]}"
            if alt in regs:
                values.append(regs[alt])
    return values


def _match_reg_condition(tl: TraceLine, cond: RegCondition) -> bool:
    values = _reg_values_for_condition(tl, cond.reg)
    for value in values:
        if cond.op == "=" and value == cond.value:
            return True
        if cond.op == "!=" and value != cond.value:
            return True
        if cond.op == ">" and value > cond.value:
            return True
        if cond.op == ">=" and value >= cond.value:
            return True
        if cond.op == "<" and value < cond.value:
            return True
        if cond.op == "<=" and value <= cond.value:
            return True
        if cond.op == "range" and cond.end is not None and cond.value <= value <= cond.end:
            return True
    return False


# ── 工具函数 ─────────────────────────────────────────────────────

def _iter_path_text_lines(path: Path) -> Generator[str, None, None]:
    """逐行读取普通文本或 .lz4 压缩 trace。"""
    if path.name.endswith(".lz4"):
        lz4_bin = shutil.which("lz4")
        if not lz4_bin:
            vendor_lz4 = cfg.vendor_dir() / cfg.LZ4_EXE
            if vendor_lz4.exists():
                lz4_bin = str(vendor_lz4)
        if not lz4_bin:
            raise RuntimeError(f"lz4 不可用，无法读取压缩 trace: {path}")
        proc = subprocess.Popen(
            [lz4_bin, "-d", "-c", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line
        finally:
            proc.stdout.close()
            stderr = ""
            if proc.stderr:
                stderr = proc.stderr.read()
                proc.stderr.close()
            return_code = proc.wait()
            if return_code != 0:
                raise RuntimeError(f"LZ4 解压失败: {path} {stderr.strip()}")
        return

    with path.open("r", encoding="utf-8", errors="replace") as f:
        yield from f


def iter_raw_lines(
    paths: list[str | Path] | None = None,
    text: str | None = None,
) -> Generator[tuple[int, str], None, None]:
    """逐行读取原始 trace 文本，保留 hook call/ret 等非指令行。"""
    if text is not None:
        for i, line in enumerate(text.splitlines(), 1):
            yield i, line
        return

    for p_str in paths or []:
        p = Path(p_str)
        if not p.exists() or not p.is_file():
            continue
        for i, line in enumerate(_iter_path_text_lines(p), 1):
            yield i, line


def iter_lines(
    paths: list[str | Path] | None = None,
    text: str | None = None,
    progress: bool = False,
) -> Generator[TraceLine, None, None]:
    """逐行解析 trace 文件。支持 paths 列表或直接传 text。"""
    if text is not None:
        for i, line in iter_raw_lines(text=text):
            tl = parse_line(line, i)
            if tl and tl.is_instruction:
                yield tl
        return

    for p_str in (paths or []):
        p = Path(p_str)
        if not p.exists() or not p.is_file():
            continue
        total = p.stat().st_size
        reported = 0
        byte_pos = 0
        for i, line in enumerate(_iter_path_text_lines(p), 1):
            byte_pos += len(line.encode("utf-8", errors="replace"))
            if progress and total > 10_000_000 and not p.name.endswith(".lz4"):
                pct = int(byte_pos * 100 / total)
                if pct >= reported + 10:
                    reported = (pct // 10) * 10
                    print(f"  [{pct}%]", end=" ", flush=True)
            tl = parse_line(line, i)
            if tl and tl.is_instruction:
                yield tl


def parse_trace_stats(
    paths: list[str | Path] | str | Path | None = None,
    text: str | None = None,
    sample_limit: int = 5,
) -> dict[str, Any]:
    """统计 trace 解析情况，帮助用户发现格式漂移或异常行。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]

    total_lines = 0
    empty_lines = 0
    instruction_lines = 0
    call_lines = 0
    ret_lines = 0
    unparsed_lines = 0
    samples: list[dict[str, Any]] = []

    def consume_line(line: str, line_no: int) -> None:
        nonlocal total_lines, empty_lines, instruction_lines, call_lines, ret_lines, unparsed_lines
        total_lines += 1
        tl = parse_line(line, line_no)
        if tl is None:
            empty_lines += 1
            return
        if tl.is_instruction:
            instruction_lines += 1
            return
        if tl.is_call:
            call_lines += 1
            return
        if tl.is_ret:
            ret_lines += 1
            return

        unparsed_lines += 1
        if len(samples) < max(0, sample_limit):
            samples.append({"line_no": line_no, "raw": tl.raw})

    for i, line in iter_raw_lines(paths=paths, text=text):
        consume_line(line, i)

    return {
        "total_lines": total_lines,
        "empty_lines": empty_lines,
        "instruction_lines": instruction_lines,
        "call_lines": call_lines,
        "ret_lines": ret_lines,
        "unparsed_lines": unparsed_lines,
        "unparsed_samples": samples,
    }


def resolve_trace_file(package: str, log_dir: str | Path | None = None) -> list[Path]:
    """定位指定包的最新 trace 日志文件。"""
    from .config import package_logs_dir, resolve_tool_root

    base = Path(log_dir) if log_dir else package_logs_dir(resolve_tool_root(), package)
    if not base.exists():
        raise FileNotFoundError(f"日志目录不存在: {base}")

    runs = sorted([d for d in base.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True)
    if not runs:
        raise FileNotFoundError(f"日志目录为空: {base}")

    for run_dir in runs:
        files = sorted(
            [f for f in run_dir.rglob("*") if f.is_file() and not f.name.endswith(".lz4") and f.stat().st_size > 0],
            key=lambda x: x.stat().st_size,
            reverse=True,
        )
        if files:
            return files[:1]  # 最大文件

        lz4_files = sorted(
            [f for f in run_dir.rglob("*.lz4") if f.is_file() and f.stat().st_size > 0],
            key=lambda x: x.stat().st_size,
            reverse=True,
        )
        if lz4_files:
            return lz4_files[:1]

    raise FileNotFoundError(f"所有 run 目录下均无可用日志文件: {base}")


def _trace_size_warnings(
    paths: list[str | Path] | None,
    command_name: str,
    passes: int,
) -> list[str]:
    """为超大 trace 输出性能提示，避免用户误以为进程卡死。"""
    if not paths:
        return []

    big_files: list[str] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            if path.is_file() and path.stat().st_size > LARGE_TRACE_WARNING_BYTES:
                big_files.append(path.name)
        except OSError:
            continue

    if not big_files:
        return []
    return [
        f"{command_name} 将以流式方式扫描超大 trace（约 {passes} 遍）："
        f"{', '.join(big_files)}。建议先用 slice 缩小范围。"
    ]

# 寄存器别名映射（w0 → x0, w1 → x1 等）
def _reg_canonical(name: str) -> str:
    """统一寄存器名：w0 → x0, 其他不变。"""
    if name.startswith("w") and name[1:].isdigit():
        return f"x{name[1:]}"
    return name
