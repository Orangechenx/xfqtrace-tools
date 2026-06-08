from __future__ import annotations

"""hook call/ret 调用栈重建。"""

import re
from pathlib import Path

from .trace_io import iter_raw_lines, resolve_trace_file

CALL_PATTERN = re.compile(r"^call\s+(?:func:|sub\s+|dlopen\b|android_dlopen_ext\b)")
RET_PATTERN = re.compile(r"^\s*ret:")


def _normalize_call_name(stripped: str) -> str | None:
    """只识别 xfQTrace 已知 hook call 前缀，未知 call 行不参与统计。"""
    if stripped.startswith("call func:"):
        name = stripped[len("call func:"):].strip()
        return name.split("(", 1)[0].strip() if "(" in name else name
    if stripped.startswith("call sub "):
        return stripped.replace("call sub ", "sub_", 1).split("(", 1)[0].strip()
    if stripped.startswith("call android_dlopen_ext"):
        return "android_dlopen_ext"
    if stripped.startswith("call dlopen"):
        return "dlopen"
    return None

def build_stack(paths: list[str | Path] | str | Path | None = None,
                text: str | None = None,
                log_dir: str | Path | None = None,
                package: str = "",
                max_depth: int = 20) -> list[dict]:
    """构建调用栈树。"""
    if isinstance(paths, (str, Path)):
        paths = [Path(paths)]
    elif paths:
        paths = [Path(p) if isinstance(p, str) else p for p in paths]

    if not paths and package:
        paths = resolve_trace_file(package, log_dir)

    # 扫描调用/返回行，保留非指令行且支持 .lz4 流式输入。
    calls: list[dict] = []
    depth = 0

    for _, line in iter_raw_lines(paths=paths, text=text):
        stripped = line.strip()
        if not stripped:
            continue
        name = _normalize_call_name(stripped)
        if name is not None:
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
