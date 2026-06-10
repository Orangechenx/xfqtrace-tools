from __future__ import annotations

"""xfq trace 分析引擎兼容门面。

具体实现已按职责拆分到 trace_io、trace_patterns、trace_search、
trace_stats、trace_branch 和 trace_taint 等模块；这里保留旧导入路径。
"""

from .trace_io import (
    LARGE_TRACE_WARNING_BYTES,
    RegCondition,
    TraceLine,
    _match_reg_condition,
    _parse_int_literal,
    _reg_canonical,
    iter_lines,
    iter_raw_lines,
    parse_line,
    parse_reg_condition,
    parse_trace_stats,
    resolve_trace_file,
)
from .trace_memory import LOAD_OPS, STORE_OPS, _extract_regs, _get_mem_addr
from .trace_patterns import (
    detect_mem_copy,
    detect_memory_access_patterns_stream,
    detect_sequential_access,
    detect_xor_loop,
    detect_xor_loop_stream,
    mempat,
    summarize,
)
from .trace_stack import build_stack, format_stack_tree
from .trace_search import grep, search_sequence
from .trace_stats import regdiff, slice_trace, stats
from .trace_branch import branch_analysis
from .trace_taint import taint_analysis, format_taint_result
from .trace_index import index_trace, query_op, query_reg, query_sequence as query_index_sequence, query_sql
from .trace_diff import diff_traces
from .trace_insights import (
    backward_slice,
    build_instruction_call_tree,
    ensure_index_cache,
    extract_strings,
    get_trace_lines,
    query_defuse,
    scan_crypto_signatures,
)

__all__ = [
    "LARGE_TRACE_WARNING_BYTES",
    "LOAD_OPS",
    "STORE_OPS",
    "RegCondition",
    "TraceLine",
    "_extract_regs",
    "_get_mem_addr",
    "_match_reg_condition",
    "_parse_int_literal",
    "_reg_canonical",
    "branch_analysis",
    "backward_slice",
    "build_stack",
    "build_instruction_call_tree",
    "detect_mem_copy",
    "detect_memory_access_patterns_stream",
    "detect_sequential_access",
    "detect_xor_loop",
    "detect_xor_loop_stream",
    "diff_traces",
    "format_stack_tree",
    "format_taint_result",
    "grep",
    "ensure_index_cache",
    "extract_strings",
    "get_trace_lines",
    "index_trace",
    "iter_lines",
    "iter_raw_lines",
    "mempat",
    "parse_line",
    "parse_reg_condition",
    "query_index_sequence",
    "query_defuse",
    "query_op",
    "query_reg",
    "query_sql",
    "parse_trace_stats",
    "regdiff",
    "resolve_trace_file",
    "search_sequence",
    "scan_crypto_signatures",
    "slice_trace",
    "stats",
    "summarize",
    "taint_analysis",
]
