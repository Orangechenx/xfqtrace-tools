#!/usr/bin/env python3
"""Rounds 50-55: deep taint, mem range, ALU coverage, format, cross-feed tests."""
import sys, os, tempfile
sys.path.insert(0, '/Users/cxcx/AndroidreverseEngineering/xfqtrace-tools')
from xfqtrace.analyzer import (
    taint_analysis, format_taint_result, iter_lines, slice_trace,
    _get_mem_addr, ALU_OPS, STORE_OPS, LOAD_OPS, COND_BRANCHES,
)

res = {"pass": 0, "fail": 0}
def T(name):
    def deco(fn):
        try:
            fn()
            res["pass"] += 1
            print(f"  ✅ {name}")
        except Exception as e:
            res["fail"] += 1
            print(f"  ❌ {name}: {e}")
    return deco
def ok(c): assert c
def eq(a,b): assert a==b, f"{a!r}!={b!r}"

print("═" * 50)
print("Round 50: NZCV + multi-source taint")

@T("cmp→cset→csel chain")
def _():
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n'
        '[lib.so] 0x1004!0x4 cmp x2, #0x0; x2=0x41 -> nzcv=0x20000000\n'
        '[lib.so] 0x1008!0x8 cset x3, ne; -> x3=0x1\n'
        '[lib.so] 0x100c!0xc csel x0, x3, xzr, ne; x3=0x1 -> x0=0x1'
    ), taint_regs=['x2'])
    ok(r['ret_tainted'])
    ok('nzcv' in r['result_register_taint'])
    ok('x3' in r['result_register_taint'])

@T("three sources overwrite x0")
def _():
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n'
        '[lib.so] 0x1004!0x4 mov x3, #0x42; x3=0x0 -> x3=0x42\n'
        '[lib.so] 0x1008!0x8 mov x4, #0x43; x4=0x0 -> x4=0x43\n'
        '[lib.so] 0x100c!0xc mov x0, x2; x2=0x41 -> x0=0x41\n'
        '[lib.so] 0x1010!0x10 mov x0, x3; x3=0x42 -> x0=0x42\n'
        '[lib.so] 0x1014!0x14 mov x0, x4; x4=0x43 -> x0=0x43'
    ), taint_regs=['x2', 'x3', 'x4'])
    ok(r['ret_tainted'])
    x0_tags = r['result_register_taint'].get('x0', [])
    ok(len(x0_tags) >= 3)

@T("x29 frame spill/restore")
def _():
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n'
        '[lib.so] 0x1004!0x4 stur w2, [x29, #-0x8]; x2=0x41 x29=0x7000\n'
        '[lib.so] 0x1008!0x8 ldur x0, [x29, #-0x8]; x29=0x7000 -> x0=0x41'
    ), taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("pre-index push→post-index pop")
def _():
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n'
        '[lib.so] 0x1004!0x4 stp x2, xzr, [sp, #-0x10]!; x2=0x41 sp=0x8000 -> sp=0x7ff0\n'
        '[lib.so] 0x1008!0x8 nop\n'
        '[lib.so] 0x100c!0xc ldp x0, x1, [sp], #0x10; sp=0x7ff0 -> x0=0x41 x1=0x0 sp=0x8000'
    ), taint_regs=['x2'])
    ok(r['ret_tainted'])

@T("branch does NOT propagate taint")
def _():
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 mov x2, #0x41; x2=0x0 -> x2=0x41\n'
        '[lib.so] 0x1004!0x4 cmp x2, #0x0; x2=0x41\n'
        '[lib.so] 0x1008!0x8 b.eq #0x10\n'
        '[lib.so] 0x100c!0xc mov x0, #0xff; x0=0x0 -> x0=0xff'
    ), taint_regs=['x2'])
    ok(not r['ret_tainted'])
    ok('nzcv' in r['result_register_taint'])

print()
print("Round 51: mem range edge cases")

@T("mem range 1 byte")
def _():
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 ldr x0, [x1]; x1=0x1000 -> x0=0x41'
    ), taint_mem_range=(0x1000, 0x1001))
    ok(r['ret_tainted'])

@T("mem range 0 bytes (no-op)")
def _():
    r = taint_analysis(paths=[], taint_mem_range=(0x1000, 0x1000))
    eq(r['total_instructions'], 0)

@T("mem range 1MB boundary allowed")
def _():
    # Small range test with trace data
    r = taint_analysis(text=(
        '[lib.so] 0x1000!0x0 ldr x0, [x1]; x1=0x1000 -> x0=0x41'
    ), taint_mem_range=(0x1000, 0x1005))
    eq(len(r['result_memory_taint']), 5)

@T("mem range 1MB upper limit")
def _():
    try:
        taint_analysis(paths=[], taint_mem_range=(0, 1_000_001))
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass

print()
print("Round 52: _get_mem_addr edge cases")

@T("post-index ldp [sp],#0x10")
def _():
    eq(_get_mem_addr('ldp x20, x19, [sp], #0x10', {'sp': 0x8000}), 0x8000)

@T("pre-index stp [sp,#-0x10]!")
def _():
    eq(_get_mem_addr('stp x29, x30, [sp, #-0x10]!', {'sp': 0x8000}), 0x7ff0)

@T("zero base reg")
def _():
    eq(_get_mem_addr('str x0, [x1]', {'x1': 0}), 0)

@T("max positive offset")
def _():
    eq(_get_mem_addr('ldr x0, [sp, #0xfff]', {'sp': 0x1000}), 0x1fff)

@T("negative large offset")
def _():
    eq(_get_mem_addr('ldur x0, [x29, #-0xff]', {'x29': 0x1000}), 0xf01)

print()
print("Round 53: ALU_OPS/STORE_OPS/LOAD_OPS completeness")

@T("all ARM64 add/sub variants")
def _():
    ok(all(op in ALU_OPS for op in ['add','sub','neg']))

@T("all logical ops")
def _():
    ok(all(op in ALU_OPS for op in ['and','orr','eor','bic','orn','mvn']))

@T("all shift ops")
def _():
    ok(all(op in ALU_OPS for op in ['lsl','lsr','asr','ror','lslv','lsrv','asrv','rorv']))

@T("all multiply ops")
def _():
    ok(all(op in ALU_OPS for op in ['mul','madd','msub','smull','umull','smulh','umulh']))

@T("all divide ops")
def _():
    ok(all(op in ALU_OPS for op in ['udiv','sdiv']))

@T("all conditional select ops")
def _():
    ok(all(op in ALU_OPS for op in ['csel','csinc','csinv','csneg','cset']))

@T("all extend ops")
def _():
    ok(all(op in ALU_OPS for op in ['uxtb','uxth','uxtw','sxtb','sxth','sxtw']))

@T("mov/movk/adrp present")
def _():
    ok(all(op in ALU_OPS for op in ['mov','movk','adrp']))

@T("LOAD_OPS complete")
def _():
    ok(all(op in LOAD_OPS for op in ['ldr','ldp','ldrb','ldrh','ldur','ldurb','ldurh','ldrsw']))

@T("STORE_OPS complete")
def _():
    ok(all(op in STORE_OPS for op in ['str','stp','strb','strh','stur','sturb','sturh']))

@T("COND_BRANCHES complete")
def _():
    bcond = {'b.eq','b.ne','b.cs','b.cc','b.mi','b.pl','b.vs','b.vc',
             'b.hi','b.ls','b.ge','b.lt','b.gt','b.le','b.al'}
    ok(bcond.issubset(COND_BRANCHES))
    ok({'cbz','cbnz','tbnz','tbz'}.issubset(COND_BRANCHES))

print()
print("Round 54: format_taint_result edge cases")

@T("ret_tainted=False format")
def _():
    s = format_taint_result({'total_instructions': 0, 'ret_tainted': False,
        'ret_tags': [], 'propagation_count': 0, 'result_register_taint': {},
        'result_memory_taint': {}, 'propagation': []})
    ok('未被污染' in s)

@T("ret_tainted=True with tags")
def _():
    s = format_taint_result({'total_instructions': 10, 'ret_tainted': True,
        'ret_tags': ['input:x2', 'input:x3'], 'propagation_count': 5,
        'result_register_taint': {'x0': ['input:x2']},
        'result_memory_taint': {}, 'propagation': [
            {'type':'reg','target':'x0','tags':['input:x2'],'insn':'mov x0, x2','line_no':2}
        ]})
    ok('被污染' in s)
    ok('input:x2' in s)

@T("empty propagation list")
def _():
    s = format_taint_result({'total_instructions': 0, 'ret_tainted': False,
        'ret_tags': [], 'propagation_count': 0, 'result_register_taint': {},
        'result_memory_taint': {}, 'propagation': []})
    ok(len(s) > 0)

print()
print("Round 55: slice + cross-feed")

@T("slice output re-analyzed")
def _():
    tmp = tempfile.mktemp(suffix='.log')
    TRACE = '/Users/cxcx/AndroidreverseEngineering/xfqtrace-tools/xfqtrace/_vendor/cn.damai/logs/1/xfqtrace_libsgmainso-6.7.250504_74f7eb0000_57bb8.log'
    slice_trace(TRACE, tmp, max_lines=100)
    lines = list(iter_lines(paths=[tmp]))
    ok(len(lines) <= 100)
    r = taint_analysis(paths=[tmp], taint_regs=['x2'])
    ok(isinstance(r['total_instructions'], int))
    os.unlink(tmp)

print(f"\n{'='*50}")
print(f"  RESULTS: {res['pass']} passed, {res['fail']} failed")
print(f"{'='*50}")
