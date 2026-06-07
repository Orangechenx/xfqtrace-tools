#!/usr/bin/env python3
"""Comprehensive test suite for xfqtrace-tools — all analysis commands on real trace data."""
import sys, json, os
sys.path.insert(0, '/Users/cxcx/AndroidreverseEngineering/xfqtrace-tools')

_results = {"passed": 0, "failed": 0}
TRACE = '/Users/cxcx/AndroidreverseEngineering/xfqtrace-tools/xfqtrace/_vendor/cn.damai/logs/1/xfqtrace_libsgmainso-6.7.250504_74f7eb0000_57bb8.log'

def T(name):
    def decorator(fn):
        try:
            fn()
            _results["passed"] += 1
            print(f"  ✅ {name}")
        except Exception as e:
            _results["failed"] += 1
            print(f"  ❌ {name}: {e}")
    return decorator

def ok(cond, msg=""):
    if not cond: raise AssertionError(msg or "expected True")
def eq(a, b, msg=""):
    if a != b: raise AssertionError(msg or f"expected {b!r}, got {a!r}")
def gt(a, b, msg=""):
    if not (a > b): raise AssertionError(msg or f"expected > {b}, got {a}")

# ═══════ Phase 2: imports ═══════
print("\n═══ Phase 2: imports ═══")

@T("all modules importable")
def _():
    import xfqtrace, xfqtrace.analyzer, xfqtrace.cli, xfqtrace.config
    import xfqtrace.core, xfqtrace.device, xfqtrace.mcp_server

from xfqtrace.analyzer import (
    parse_line, TraceLine, iter_lines, _parse_regs, _extract_regs,
    _get_mem_addr, _reg_canonical, summarize, build_stack, grep,
    slice_trace, stats, regdiff, mempat, branch_analysis,
    taint_analysis, format_taint_result, detect_xor_loop, detect_mem_copy,
    STORE_OPS, LOAD_OPS, ALU_OPS, COND_BRANCHES, resolve_trace_file, format_stack_tree,
)
from xfqtrace.config import resolve_tool_root, package_logs_dir

# ═══════ Phase 3: parse_line ═══
print("\n═══ Phase 3: parse_line ═══")

@T("normal instruction line")
def _():
    tl = parse_line('[lib.so] 0x1000!0x0 mov x0, #0x1; x0=0x0 -> x0=0x1', 1)
    ok(tl.is_instruction); eq(tl.module, 'lib.so')
    eq(tl.address, 0x1000); eq(tl.offset, 0x0)
    eq(tl.insn, 'mov x0, #0x1'); eq(tl.regs_before.get('x0'), 0)
    eq(tl.regs_after.get('x0'), 1)

@T("call func line")
def _():
    tl = parse_line('call func: test(x0=1)', 1)
    ok(tl.is_call); ok('test' in tl.call_name)

@T("call without func prefix (only 'call func:' is supported)")
def _():
    tl = parse_line('call sub test()', 1)
    ok(not tl.is_call)  # only 'call func:' prefix is recognized

@T("ret line")
def _():
    tl = parse_line('ret: 0x1', 1)
    ok(tl.is_ret)

@T("empty line returns None")
def _():
    ok(parse_line('', 1) is None)

@T("non-trace line not parsed as instruction")
def _():
    tl = parse_line('some random text', 1)
    ok(not tl.is_instruction and not tl.is_call and not tl.is_ret)

@T("module with parentheses")
def _():
    tl = parse_line('[libtest-6.7.so (arm64)] 0x1000!0x0 nop', 1)
    ok(tl.is_instruction); ok('arm64' in tl.module)

@T("instruction with comma in brackets")
def _():
    tl = parse_line('[lib.so] 0x1000!0x0 ldr x0, [x1, #0x4]; x1=0x5000 -> x0=0x41', 1)
    ok(tl.is_instruction); ok('[x1' in tl.insn)

@T("CRLF line ending")
def _():
    tl = parse_line('[lib.so] 0x1000!0x0 nop\r\n', 1)
    ok(tl.is_instruction); eq(tl.insn, 'nop')

@T("tab-separated fields")
def _():
    tl = parse_line('[lib.so]\t0x1000!0x0\tmov x0, #0x1', 1)
    ok(tl.is_instruction)

@T("no regs after instruction")
def _():
    tl = parse_line('[lib.so] 0x1000!0x0 nop', 1)
    ok(tl.is_instruction); eq(len(tl.regs_before), 0)

@T("semicolon but no arrow")
def _():
    tl = parse_line('[lib.so] 0x1000!0x0 mov x0, #0x1; x0=0x0', 2)
    eq(tl.regs_before, {'x0': 0}); eq(len(tl.regs_after), 0)

# ═══════ Phase 4: _parse_regs ═══════
print("\n═══ Phase 4: _parse_regs ═══")

@T("x registers")
def _(): eq(_parse_regs('x0=0x1234 x1=0x5678'), {'x0': 0x1234, 'x1': 0x5678})

@T("w registers")
def _(): eq(_parse_regs('w0=0x41 w11=0x0'), {'w0': 0x41, 'w11': 0})

@T("sp register")
def _(): eq(_parse_regs('sp=0x8000'), {'sp': 0x8000})

@T("decimal values")
def _(): eq(_parse_regs('x0=5'), {'x0': 5})

@T("uppercase hex")
def _(): eq(_parse_regs('x0=0xABCD'), {'x0': 0xABCD})

@T("0X prefix")
def _(): eq(_parse_regs('x0=0X1234'), {'x0': 0x1234})

@T("negative decimal")
def _(): eq(_parse_regs('x0=-5'), {'x0': -5})

@T("negative hex")
def _(): eq(_parse_regs('x0=-0x5'), {'x0': -5})

@T("comma-separated regs")
def _(): eq(_parse_regs('x0=0x1, x1=0x2'), {'x0': 1, 'x1': 2})

@T("system registers (nzcv, cpsr)")
def _(): eq(_parse_regs('nzcv=0x1 cpsr=0x60000000'), {'nzcv': 1, 'cpsr': 0x60000000})

@T("empty string")
def _(): eq(_parse_regs(''), {})

@T("no match")
def _(): eq(_parse_regs('hello world'), {})

# ═══════ Phase 5: utility functions ═══════
print("\n═══ Phase 5: utility functions ═══")

@T("_reg_canonical w->x")
def _(): eq(_reg_canonical('w11'), 'x11')
@T("_reg_canonical x->x")
def _(): eq(_reg_canonical('x2'), 'x2')
@T("_reg_canonical sp")
def _(): eq(_reg_canonical('sp'), 'sp')
@T("_reg_canonical nzcv")
def _(): eq(_reg_canonical('nzcv'), 'nzcv')

@T("_extract_regs add")
def _(): eq(_extract_regs('add x0, x1, #0x5'), ['x0', 'x1'])
@T("_extract_regs eor")
def _(): eq(_extract_regs('eor w11, w11, w12'), ['w11', 'w11', 'w12'])
@T("_extract_regs stp")
def _(): eq(_extract_regs('stp x29, x30, [sp, #0x30]'), ['x29', 'x30'])
@T("_extract_regs ldp")
def _(): eq(_extract_regs('ldp x4, x5, [sp, #0x10]'), ['x4', 'x5'])
@T("_extract_regs strb")
def _(): eq(_extract_regs('strb w0, [x1, #0x4]'), ['w0'])
@T("_extract_regs csel")
def _(): eq(_extract_regs('csel x0, x1, x2, eq'), ['x0', 'x1', 'x2'])
@T("_extract_regs uxtb")
def _(): eq(_extract_regs('uxtb x0, w2'), ['x0', 'w2'])
@T("_extract_regs madd (5 operands)")
def _(): eq(_extract_regs('madd x0, x2, x3, x4'), ['x0', 'x2', 'x3', 'x4'])
@T("_extract_regs excludes sp from brackets")
def _(): eq(_extract_regs('str x0, [sp, #0x10]'), ['x0'])

@T("_get_mem_addr str + offset")
def _(): eq(_get_mem_addr('str x0, [x1, #0x4]', {'x1': 0x5000}), 0x5004)
@T("_get_mem_addr strb")
def _(): eq(_get_mem_addr('strb w0, [x1, #0x1]', {'x1': 0x5000}), 0x5001)
@T("_get_mem_addr sp base")
def _(): eq(_get_mem_addr('str x0, [sp, #0x10]', {'sp': 0x8000}), 0x8010)
@T("_get_mem_addr negative offset")
def _(): eq(_get_mem_addr('stur w0, [x29, #-0x8]', {'x29': 0x7000}), 0x6ff8)
@T("_get_mem_addr no offset")
def _(): eq(_get_mem_addr('str x0, [x1]', {'x1': 0x5000}), 0x5000)

# ═══════ Phase 6: iter_lines ═══════
print("\n═══ Phase 6: iter_lines ═══")

@T("text mode")
def _(): eq(sum(1 for _ in iter_lines(text='[lib.so] 0x1000!0x0 mov x0, #0x1')), 1)
@T("text empty")
def _(): eq(sum(1 for _ in iter_lines(text='')), 0)
@T("paths nonexistent (silent skip)")
def _(): eq(sum(1 for _ in iter_lines(paths=['/nonexistent.log'])), 0)
@T("paths empty list")
def _(): eq(sum(1 for _ in iter_lines(paths=[])), 0)
@T("paths directory (skip)")
def _():
    import tempfile; d = tempfile.mkdtemp()
    c = sum(1 for _ in iter_lines(paths=[d]))
    os.rmdir(d); eq(c, 0)

# ═══════ Phase 7: real trace analyzers ═══════
print("\n═══ Phase 7: real trace analyzers ═══")

lines = list(iter_lines(paths=[TRACE]))

@T("real trace has 9000+ instructions")
def _(): gt(len(lines), 9000)

@T("100% instruction lines parse")
def _():
    bad = 0; total = 0
    for line in open(TRACE, encoding='utf-8', errors='replace'):
        total += 1
        s = line.strip()
        if s.startswith('['):
            tl = parse_line(line, total)
            if not tl.is_instruction:
                bad += 1
    if bad:
        raise AssertionError(f"{bad}/{total} instruction lines failed parse")

@T("summarize real data")
def _():
    r = summarize(paths=[TRACE])
    gt(r['total_instructions'], 0); gt(len(r['patterns']), 0)
    gt(len(r['top_opcodes']), 0)

@T("build_stack real data")
def _():
    r = build_stack(paths=TRACE)
    gt(len(r), 0)

@T("grep by opcode")
def _():
    r = grep(paths=TRACE, opcode='eor', max_results=5)
    eq(len(r), 5)

@T("grep by reg_filter")
def _():
    r = grep(paths=TRACE, reg_filter={'w11': 0}, max_results=3)
    gt(len(r), 0)

@T("stats real data")
def _():
    r = stats(paths=TRACE)
    gt(r['total_instructions'], 0); gt(r['total_calls'], 0)

@T("regdiff real data")
def _():
    r = regdiff(paths=[TRACE])
    gt(len(r), 0)

@T("regdiff specific registers")
def _():
    r = regdiff(paths=[TRACE], target_regs=['x2', 'w11'])
    gt(len(r), 0)

@T("mempat real data")
def _():
    r = mempat(paths=[TRACE])
    gt(len(r), 0)

@T("branch_analysis real data")
def _():
    r = branch_analysis(paths=[TRACE])
    gt(len(r), 0)
    total_t = sum(b['taken'] for b in r)
    total_nt = sum(b['not_taken'] for b in r)
    gt(total_t + total_nt, 0, f"total taken+not_taken={total_t}+{total_nt} should be > 0")

@T("resolve_trace_file by package")
def _():
    r = resolve_trace_file('cn.damai')
    gt(len(r), 0); ok(r[0].exists())

@T("detect_xor_loop real data")
def _():
    r = detect_xor_loop(lines)
    gt(len(r), 0)

@T("detect_mem_copy real data")
def _():
    r = detect_mem_copy(lines)
    gt(len(r), 0)

# ═══════ Phase 8: taint_analysis ═══════
print("\n═══ Phase 8: taint_analysis ═══")

@T("taint real trace x2 → x0")
def _():
    r = taint_analysis(paths=[TRACE], taint_regs=['x2'])
    ok(r['ret_tainted']); gt(r['propagation_count'], 0)
    gt(len(r['result_register_taint']), 0)

@T("taint summary mode omits propagation")
def _():
    r = taint_analysis(paths=[TRACE], taint_regs=['x2'], summary=True)
    ok(r['ret_tainted']); ok('propagation' not in r)

@T("taint mov x0, x2")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 mov x0, x2; x2=0x41 -> x0=0x41', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint add")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x1; x2=0x0 -> x2=0x1\n[lib.so] 0x1004!0x4 add x0, x2, #0x1; x2=0x1 -> x0=0x2', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint eor")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 eor x0, x2, x2; x2=0x41 -> x0=0x0', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint str→ldr stack")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 str x2, [sp]; x2=0x41 sp=0x8000\n[lib.so] 0x1008!0x8 ldr x0, [sp]; sp=0x8000 -> x0=0x41', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint strb→ldrb byte")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 strb w2, [sp]; x2=0x41 sp=0x8000\n[lib.so] 0x1008!0x8 ldrb w0, [sp]; sp=0x8000 -> w0=0x41', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint stp→ldp dual (x1 clean)")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 stp x2, xzr, [sp, #0x10]; x2=0x41 sp=0x8000\n[lib.so] 0x1008!0x8 ldp x0, x1, [sp, #0x10]; sp=0x8000 -> x0=0x41 x1=0x0', taint_regs=['x2'])
    ok(r['ret_tainted']); ok('x1' not in r['result_register_taint'])  # xzr has no taint

@T("taint neg")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 neg x0, x2; x2=0x41 -> x0=0xffffffbf', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint mvn")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 mvn x0, x2; x2=0x41 -> x0=0xffffffbe', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint madd")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x7; x2=0x0 -> x2=0x7\n[lib.so] 0x1004!0x4 mov x3, #0x3; x3=0x0 -> x3=0x3\n[lib.so] 0x1008!0x8 mov x4, #0x5; x4=0x0 -> x4=0x5\n[lib.so] 0x100c!0xc madd x0, x2, x3, x4; x2=0x7 x3=0x3 x4=0x5 -> x0=0x1a', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint uxtb extension")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 uxtb x0, w2; x2=0x41 -> x0=0x41', taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("taint tst→cset flag")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 tst x2, #0x1; x2=0x41\n[lib.so] 0x1008!0x8 cset x0, ne; -> x0=0x1', taint_regs=['x2'])
    ok(r['ret_tainted']); ok('nzcv' in r['result_register_taint'])

@T("taint multi-source (x2+x3)")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 mov x3, #0x42; x3=0x0 -> x3=0x42\n[lib.so] 0x1008!0x8 add x0, x2, x3; x2=0x41 x3=0x42 -> x0=0x83', taint_regs=['x2', 'x3'])
    ok(r['ret_tainted']); ok('input:x2' in r['ret_tags'] and 'input:x3' in r['ret_tags'])

@T("taint w→x alias canonical")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov w2, #0x41; w2=0x0 -> w2=0x41\n[lib.so] 0x1004!0x4 mov x0, x2; x2=0x41 -> x0=0x41', taint_regs=['w2'])
    ok(r['ret_tainted'])

@T("taint empty trace")
def _():
    r = taint_analysis(paths=[], taint_regs=['x2'])
    eq(r['total_instructions'], 0); eq(r['ret_tainted'], False)

@T("taint mem range")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 ldr x0, [x1]; x1=0x1000 -> x0=0x41', taint_mem_range=(0x1000, 0x1001))
    ok(r['ret_tainted'])

@T("taint mem range too large")
def _():
    try:
        taint_analysis(paths=[], taint_mem_range=(0, 2000000))
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass

@T("taint mem range reversed")
def _():
    try:
        taint_analysis(paths=[], taint_mem_range=(200, 100))
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass

@T("format_taint_result normal")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 mov x0, x2; x2=0x41 -> x0=0x41', taint_regs=['x2'])
    s = format_taint_result(r, max_prop=50)
    ok(len(s) > 0)

@T("format_taint_result max_prop=-1 no crash")
def _():
    r = taint_analysis(text='[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n[lib.so] 0x1004!0x4 mov x0, x2; x2=0x41 -> x0=0x41', taint_regs=['x2'])
    s = format_taint_result(r, max_prop=-1)
    ok(len(s) > 0)

# ═══════ Phase 9: detect functions ═══════
print("\n═══ Phase 9: detect functions ═══")

@T("detect_xor_loop with b.ne backward")
def _():
    text = '[lib.so] 0x1000!0x0 eor w11, w11, w12\n[lib.so] 0x1004!0x4 add x15, x15, #0x1\n[lib.so] 0x1008!0x8 b.ne #-0x4c'
    r = detect_xor_loop(list(iter_lines(text=text)))
    eq(len(r), 1)

@T("detect_xor_loop with tbnz backward")
def _():
    text = '[lib.so] 0x1000!0x0 eor w11, w11, w12\n[lib.so] 0x1004!0x4 add x15, x15, #0x1\n[lib.so] 0x1008!0x8 tbnz w0, #0x0, #-0x4c'
    r = detect_xor_loop(list(iter_lines(text=text)))
    eq(len(r), 1)

@T("detect_xor_loop forward (should not detect)")
def _():
    text = '[lib.so] 0x1000!0x0 eor w11, w11, w12\n[lib.so] 0x1004!0x4 add x15, x15, #0x1\n[lib.so] 0x1008!0x8 b.eq #0x20'
    r = detect_xor_loop(list(iter_lines(text=text)))
    eq(len(r), 0)

@T("detect_mem_copy str sequence")
def _():
    text = '[lib.so] 0x1000!0x0 str x0, [x1, #0x0]; x1=0x5000\n[lib.so] 0x1004!0x4 str x0, [x1, #0x8]; x1=0x5000\n[lib.so] 0x1008!0x8 str x0, [x1, #0x10]; x1=0x5000'
    r = detect_mem_copy(list(iter_lines(text=text)))
    eq(len(r), 1); eq(r[0]['stride'], 8)

@T("detect_mem_copy strb sequence")
def _():
    text = '[lib.so] 0x1000!0x0 strb w0, [x1, #0x0]; x1=0x5000\n[lib.so] 0x1004!0x4 strb w0, [x1, #0x1]; x1=0x5000\n[lib.so] 0x1008!0x8 strb w0, [x1, #0x2]; x1=0x5000'
    r = detect_mem_copy(list(iter_lines(text=text)))
    eq(len(r), 1); eq(r[0]['stride'], 1)

@T("detect_mem_copy only 2 writes (no pattern)")
def _():
    text = '[lib.so] 0x1000!0x0 str x0, [x1, #0x0]; x1=0x5000\n[lib.so] 0x1004!0x4 str x0, [x1, #0x8]; x1=0x5000'
    r = detect_mem_copy(list(iter_lines(text=text)))
    eq(len(r), 0)

# ═══════ Phase 10: CLI commands on real data ═══════
print("\n═══ Phase 10: CLI --json output validation ═══")
import subprocess
PY = '/Users/cxcx/AndroidreverseEngineering/.venv-frida162/bin/python3'

def run_cli(args):
    cmd = [PY, '-m', 'xfqtrace'] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"CLI error: {r.stderr[:200]}")
    return r.stdout

@T("summarize --json keys")
def _():
    d = json.loads(run_cli(['summarize', TRACE, '--json']))
    ok('total_instructions' in d); ok('patterns' in d); ok('top_opcodes' in d)

@T("stack --json keys")
def _():
    d = json.loads(run_cli(['stack', TRACE, '--json']))
    ok('calls' in d); ok('count' in d)

@T("grep --json keys")
def _():
    d = json.loads(run_cli(['grep', TRACE, '--opcode', 'eor', '--max', '3', '--json']))
    ok('matches' in d); ok('results' in d)

@T("stats --json keys")
def _():
    d = json.loads(run_cli(['stats', TRACE, '--json']))
    ok('total_instructions' in d); ok('total_calls' in d)

@T("regdiff --json keys")
def _():
    d = json.loads(run_cli(['regdiff', TRACE, '--json']))
    ok('registers' in d)

@T("mempat --json keys")
def _():
    d = json.loads(run_cli(['mempat', TRACE, '--json']))
    ok('patterns' in d)

@T("branch --json keys")
def _():
    d = json.loads(run_cli(['branch', TRACE, '--json']))
    ok('branches' in d)

@T("taint --json keys")
def _():
    d = json.loads(run_cli(['taint', TRACE, '--taint', 'x2', '--json']))
    for k in ['total_instructions','ret_tainted','ret_tags','propagation_count','result_register_taint']:
        ok(k in d, f"missing key: {k}")

# ═══════ Phase 11: slice command ═══════
print("\n═══ Phase 11: slice command ═══")

import tempfile
tmp_out = tempfile.mktemp(suffix='.log')

@T("slice --max 5 --json")
def _():
    d = json.loads(run_cli(['slice', TRACE, '--max', '5', '--output', tmp_out, '--json']))
    eq(d['written_lines'], 5)
    # total_lines should be full file length
    gt(d['total_lines'], 9000)

@T("slice --line-start/end")
def _():
    d = json.loads(run_cli(['slice', TRACE, '--line-start', '10', '--line-end', '20', '--output', tmp_out, '--json']))
    eq(d['written_lines'], 11)

@T("slice --pc-range")
def _():
    d = json.loads(run_cli(['slice', TRACE, '--pc-range', '0x74f7f05080-0x74f7f05120', '--output', tmp_out, '--json']))
    gt(d['written_lines'], 0)

# ═══════ Phase 12: real device commands ═══════
print("\n═══ Phase 12: real device commands ═══")

@T("doctor on real device")
def _():
    d = json.loads(run_cli(['doctor']))
    ok(d['device']['connected'])
    ok(d['frida']['server_running'])

@T("list-logs cn.damai")
def _():
    d = json.loads(run_cli(['list-logs', '-p', 'cn.damai']))
    ok(d['exists']); gt(len(d['runs']), 0)

@T("preview-log cn.damai")
def _():
    d = json.loads(run_cli(['preview-log', '-p', 'cn.damai']))
    ok('text' in d)

@T("info")
def _():
    d = json.loads(run_cli(['info']))
    ok('exists' in d)

@T("logcat command")
def _():
    d = json.loads(run_cli(['logcat']))
    ok('command' in d)

# ═══════ Phase 13: edge cases CLI ═══════
print("\n═══ Phase 13: CLI edge cases ═══")

@T("taint --taint x99 rejected")
def _():
    r = subprocess.run([PY, '-m', 'xfqtrace', 'taint', TRACE, '--taint', 'x99'], capture_output=True, text=True)
    ok(r.returncode != 0); ok('无效的寄存器名' in r.stderr)

@T("taint --taint-mem bad format rejected")
def _():
    r = subprocess.run([PY, '-m', 'xfqtrace', 'taint', TRACE, '--taint-mem', 'xxx'], capture_output=True, text=True)
    ok(r.returncode != 0)

@T("taint --taint sp accepted")
def _():
    r = subprocess.run([PY, '-m', 'xfqtrace', 'taint', TRACE, '--taint', 'sp', '--summary'], capture_output=True, text=True)
    ok(r.returncode == 0)

@T("branch --min-rate 200 (no results, no crash)")
def _():
    r = subprocess.run([PY, '-m', 'xfqtrace', 'branch', TRACE, '--min-rate', '200'], capture_output=True, text=True)
    ok(r.returncode == 0); ok('未发现' in r.stdout)

@T("grep --pc-range bad format rejected")
def _():
    r = subprocess.run([PY, '-m', 'xfqtrace', 'grep', TRACE, '--pc-range', 'xxx'], capture_output=True, text=True)
    ok(r.returncode != 0)

@T("empty file taint")
def _():
    from pathlib import Path
    empty = tempfile.mktemp(suffix='.log')
    Path(empty).touch()
    d = json.loads(run_cli(['taint', empty, '--taint', 'x2', '--json']))
    eq(d['total_instructions'], 0); eq(d['ret_tainted'], False)
    os.unlink(empty)

# ═══════ Phase 14: summarize edge ═══════
print("\n═══ Phase 14: summarize edge cases ═══")

@T("summarize with package name")
def _():
    d = json.loads(run_cli(['summarize', 'cn.damai', '--json']))
    gt(d['total_instructions'], 0)

@T("stats with package name")
def _():
    d = json.loads(run_cli(['stats', 'cn.damai', '--json']))
    gt(d['total_instructions'], 0)

# ═══════ Phase 15: stack edge ═══════
print("\n═══ Phase 15: stack edge cases ═══")

@T("format_stack_tree empty")
def _(): eq(format_stack_tree([]), '')

@T("format_stack_tree single")
def _(): ok('├─' in format_stack_tree([{'name':'f','depth':0,'line':'call'}]))

@T("format_stack_tree collapsed repeats")
def _():
    calls = [{'name':'f','depth':0,'line':'call'}, {'name':'f','depth':1,'line':'call'},
             {'name':'f','depth':2,'line':'call'}, {'name':'g','depth':3,'line':'call'}]
    s = format_stack_tree(calls)
    ok('...' in s)

# ═══════ Final ═══════
print(f"\n{'='*60}")
print(f"  RESULTS: {_results['passed']} passed, {_results['failed']} failed")
print(f"{'='*60}")

# Cleanup
try: os.unlink(tmp_out)
except: pass
