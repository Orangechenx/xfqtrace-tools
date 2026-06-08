from __future__ import annotations

"""ARM64 内存操作数和寄存器寻址辅助函数。"""

import re

from .trace_io import _parse_int_literal, _reg_canonical

# str/stp 类内存写指令
STORE_OPS = {"str", "stp", "strb", "strh", "stur", "sturb", "sturh"}
# ldr/ldp 类内存读指令
LOAD_OPS = {"ldr", "ldp", "ldrb", "ldrh", "ldur", "ldurb", "ldurh", "ldrsw"}
# ALU 类（结果继承所有源操作数的污点）
ALU_OPS = {"add", "sub", "eor", "and", "orr", "bic", "orn",
           "lsl", "lsr", "asr", "mul", "udiv", "sdiv",
           "csel", "csinc", "csinv", "csneg", "cset",
           "madd", "msub", "smull", "umull", "smulh", "umulh",
           "movk", "adrp",
           "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw",
           "mov", "mvn", "neg", "lslv", "lsrv", "asrv", "ror", "rorv"}


# 提取指令中的寄存器操作数
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


def _lookup_reg_value(regs: dict[str, int], name: str) -> int | None:
    """按 w/x 别名查找寄存器值，避免 trace 只记录其中一种宽度时漏算地址。"""
    if name in regs:
        return regs[name]
    canon = _reg_canonical(name)
    if canon in regs:
        return regs[canon]
    if canon.startswith("x"):
        alt = f"w{canon[1:]}"
        if alt in regs:
            return regs[alt]
    return None


def _sign_extend(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    sign_bit = 1 << (bits - 1)
    value &= mask
    return value - (1 << bits) if value & sign_bit else value


def _apply_register_extend(index_val: int, extend: str) -> int:
    """应用 ARM64 register offset 中的 uxt*/sxt* 扩展语义。"""
    op = extend.lower().split()[0] if extend else ""
    bit_widths = {
        "uxtb": 8,
        "uxth": 16,
        "uxtw": 32,
        "sxtb": 8,
        "sxth": 16,
        "sxtw": 32,
    }
    bits = bit_widths.get(op)
    if bits is None:
        return index_val
    if op.startswith("u"):
        return index_val & ((1 << bits) - 1)
    return _sign_extend(index_val, bits)


def _get_mem_addr(insn: str, regs_before: dict[str, int]) -> int | None:
    """从常见 ARM64 内存操作数计算有效地址。"""
    m = re.search(r"\[(?P<inner>[^\]]+)\](?P<pre>!)?(?:\s*,\s*(?P<post>#[^,\s]+))?", insn)
    if not m:
        return None

    parts = [p.strip() for p in m.group("inner").split(",") if p.strip()]
    if not parts:
        return None

    base_reg = parts[0]
    base_val = _lookup_reg_value(regs_before, base_reg)
    if base_val is None:
        return None

    # post-index: [base], #offset 的有效地址是更新前的 base。
    if m.group("post") and len(parts) == 1:
        return base_val

    if len(parts) == 1:
        return base_val

    second = parts[1]
    if second.startswith("#"):
        offset = _parse_int_literal(second)
        if offset is None:
            return None
        return base_val + offset

    index_val = _lookup_reg_value(regs_before, second)
    if index_val is None:
        return None

    scale = 0
    extend = ""
    if len(parts) >= 3:
        extend = " ".join(parts[2:])
        index_val = _apply_register_extend(index_val, extend)
        m_shift = re.search(r"#(?P<scale>\d+)", extend)
        if m_shift:
            scale = int(m_shift.group("scale"))
    if scale:
        index_val <<= scale
    return base_val + index_val
