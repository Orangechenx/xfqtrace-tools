from __future__ import annotations

"""多 trace 覆盖和顺序差异对比。"""

from collections import Counter
from itertools import zip_longest
from pathlib import Path
from typing import Any

from .trace_io import TraceLine, iter_lines, iter_raw_lines, parse_line


def _line_to_result(tl: TraceLine, *, kind: str = "instruction") -> dict[str, Any]:
    return {
        "kind": kind,
        "line_no": tl.line_no,
        "module": tl.module,
        "address": hex(tl.address),
        "offset": hex(tl.offset),
        "insn": tl.insn,
        "raw": tl.raw,
    }


def _opcode(insn: str) -> str:
    return insn.split(maxsplit=1)[0].lower() if insn.strip() else ""


def _coverage_key(tl: TraceLine) -> tuple[str, int]:
    return tl.module, tl.offset


def _signature(tl: TraceLine, *, ignore_operands: bool = False) -> tuple[str, int, str]:
    insn_part = _opcode(tl.insn) if ignore_operands else tl.insn
    return tl.module, tl.offset, insn_part


def _event_signature(event: dict[str, Any], *, ignore_operands: bool = False) -> tuple[Any, ...]:
    kind = event["kind"]
    if kind == "instruction":
        insn_part = _opcode(str(event["insn"])) if ignore_operands else event["insn"]
        return kind, event["module"], event["offset"], insn_part
    if kind == "call":
        return kind, event.get("call_name", "")
    return kind, event.get("raw", "")


def _format_key(key: tuple[str, int]) -> str:
    return f"{key[0]}:{hex(key[1])}"


def _collect_summary(
    paths: list[str | Path] | None = None,
    text: str | None = None,
) -> tuple[dict[str, Any], set[tuple[str, int]], dict[tuple[str, int], dict[str, Any]]]:
    opcode_counts: Counter[str] = Counter()
    module_counts: Counter[str] = Counter()
    offsets: set[tuple[str, int]] = set()
    samples: dict[tuple[str, int], dict[str, Any]] = {}
    instruction_count = 0

    for tl in iter_lines(paths=paths, text=text):
        instruction_count += 1
        opcode_counts[_opcode(tl.insn)] += 1
        module_counts[tl.module] += 1
        key = _coverage_key(tl)
        offsets.add(key)
        samples.setdefault(key, _line_to_result(tl))

    return (
        {
            "instruction_count": instruction_count,
            "opcode_counts": dict(sorted(opcode_counts.items())),
            "module_counts": dict(sorted(module_counts.items())),
        },
        offsets,
        samples,
    )


def _call_to_result(tl: TraceLine) -> dict[str, Any]:
    return {
        "kind": "call",
        "line_no": tl.line_no,
        "call_name": tl.call_name,
        "raw": tl.raw,
    }


def _ret_to_result(tl: TraceLine) -> dict[str, Any]:
    return {
        "kind": "ret",
        "line_no": tl.line_no,
        "raw": tl.raw,
    }


def _iter_events(
    paths: list[str | Path] | None = None,
    text: str | None = None,
    *,
    include_calls: bool = False,
):
    if not include_calls:
        for tl in iter_lines(paths=paths, text=text):
            yield _line_to_result(tl)
        return

    for line_no, raw in iter_raw_lines(paths=paths, text=text):
        tl = parse_line(raw, line_no)
        if tl is None:
            continue
        if tl.is_call:
            yield _call_to_result(tl)
        elif tl.is_ret:
            yield _ret_to_result(tl)
        elif tl.is_instruction:
            yield _line_to_result(tl)


def _find_first_divergence(
    left_paths: list[str | Path] | None = None,
    right_paths: list[str | Path] | None = None,
    left_text: str | None = None,
    right_text: str | None = None,
    *,
    ignore_operands: bool = False,
    include_calls: bool = False,
) -> dict[str, Any] | None:
    left_iter = _iter_events(paths=left_paths, text=left_text, include_calls=include_calls)
    right_iter = _iter_events(paths=right_paths, text=right_text, include_calls=include_calls)
    for index, (left, right) in enumerate(zip_longest(left_iter, right_iter), 1):
        if left is None:
            return {"index": index, "left": None, "right": right}
        if right is None:
            return {"index": index, "left": left, "right": None}
        if _event_signature(left, ignore_operands=ignore_operands) != _event_signature(right, ignore_operands=ignore_operands):
            return {
                "index": index,
                "left": left,
                "right": right,
            }
    return None


def _sample_offsets(
    keys: set[tuple[str, int]],
    samples: dict[tuple[str, int], dict[str, Any]],
    max_samples: int,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in sorted(keys, key=lambda item: (item[0], item[1]))[:max(0, max_samples)]:
        item = samples.get(key, {"module": key[0], "offset": hex(key[1])}).copy()
        item["key"] = _format_key(key)
        result.append(item)
    return result


def diff_traces(
    left: str | Path | None = None,
    right: str | Path | None = None,
    *,
    left_text: str | None = None,
    right_text: str | None = None,
    max_samples: int = 20,
    ignore_operands: bool = False,
    include_calls: bool = False,
) -> dict[str, Any]:
    """对比两个 trace 的指令覆盖、opcode 分布和第一处顺序分歧。"""
    left_paths = [Path(left)] if left is not None else None
    right_paths = [Path(right)] if right is not None else None
    if left_paths is None and left_text is None:
        raise ValueError("请提供 left 路径或 left_text")
    if right_paths is None and right_text is None:
        raise ValueError("请提供 right 路径或 right_text")

    left_summary, left_offsets, left_samples = _collect_summary(left_paths, left_text)
    right_summary, right_offsets, right_samples = _collect_summary(right_paths, right_text)

    shared = left_offsets & right_offsets
    left_only = left_offsets - right_offsets
    right_only = right_offsets - left_offsets

    return {
        "left": left_summary,
        "right": right_summary,
        "coverage": {
            "shared_offsets_count": len(shared),
            "left_only_offsets_count": len(left_only),
            "right_only_offsets_count": len(right_only),
            "left_coverage_ratio": round(len(shared) / len(left_offsets) * 100, 2) if left_offsets else 0,
            "right_coverage_ratio": round(len(shared) / len(right_offsets) * 100, 2) if right_offsets else 0,
            "left_only_samples": _sample_offsets(left_only, left_samples, max_samples),
            "right_only_samples": _sample_offsets(right_only, right_samples, max_samples),
        },
        "first_divergence": _find_first_divergence(
            left_paths,
            right_paths,
            left_text,
            right_text,
            ignore_operands=ignore_operands,
            include_calls=include_calls,
        ),
    }
