from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
"""xfqtrace Python 包的根目录 (…/xfqtrace/xfqtrace/)。"""

PROJECT_ROOT = PACKAGE_ROOT.parents[1]
"""项目根目录 (…/AndroidreverseEngineering/)。"""

DEFAULT_TOOL_DIR_NAME = "xfqtrace v1.3 (带examples脚本)"
"""原始工具目录名，内含案例配置、bypass 脚本等资产。"""

DEFAULT_TEMPLATE = "半自动化trace.js"
BYPASS_DIR = "scripts"
BIN_DIR = "bin"
ENGINE_SO = "libxfqtrace.so"
LZ4_EXE = "lz4.exe"


def vendor_dir() -> Path:
    """本包自带的 _vendor 目录（内置引擎 SO + lz4 + 案例 + bypass 脚本）。"""
    return PACKAGE_ROOT / "_vendor"


def resolve_tool_root(explicit: str | Path | None = None) -> Path:
    """定位原始工具目录，存放案例配置、bypass 脚本等。

    优先: 传入值 > 环境变量 > 包内 vendor/ > 项目旁 > pwd。
    不保证目录一定存在。
    """
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("XFQTRACE_TOOL_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    # 包内 vendor/ 自包含目录
    builtin = vendor_dir()
    if builtin.exists() and _has_minimal_assets(builtin):
        return builtin.resolve()
    candidates = [
        PROJECT_ROOT / DEFAULT_TOOL_DIR_NAME,
        Path.cwd() / DEFAULT_TOOL_DIR_NAME,
        PROJECT_ROOT / "vendor" / DEFAULT_TOOL_DIR_NAME,
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    return candidates[0]


def _has_minimal_assets(tool_root: Path) -> bool:
    """检查目录是否包含最简资产（默认模板或至少一个带模板的案例目录）。"""
    if (tool_root / DEFAULT_TEMPLATE).exists():
        return True
    return any(
        p.is_dir() and "." in p.name and (p / DEFAULT_TEMPLATE).exists()
        for p in tool_root.iterdir()
    )


def tool_asset(tool_root: Path, *parts: str) -> Path:
    """工具资产目录下的文件路径。"""
    return tool_root.joinpath(*parts)


def engine_so_path(tool_root: str | Path, explicit: str | Path | None = None) -> Path:
    """引擎 SO 路径。"""
    if isinstance(tool_root, str):
        tool_root = Path(tool_root)
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.exists():
            return p

    env_so = os.environ.get("XFQTRACE_SO")
    if env_so:
        p = Path(env_so).expanduser().resolve()
        if p.exists():
            return p

    # 搜索候选位置
    candidates = [
        vendor_dir() / ENGINE_SO,            # 包内 _vendor/（优先）
        tool_asset(tool_root, BIN_DIR, ENGINE_SO),  # 工具目录 bin/
        tool_root / ENGINE_SO,               # 工具目录根
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    return candidates[0]


def lz4_exe_path(tool_root: Path) -> Path:
    """LZ4 可执行路径，优先系统 lz4，Windows 回退 vendor/lz4.exe。"""
    # 系统 lz4（macOS/Linux）
    import shutil
    system_lz4 = shutil.which("lz4")
    if system_lz4:
        return Path(system_lz4)

    # Windows: 用包内自带的 lz4.exe
    vendor_lz4 = vendor_dir() / LZ4_EXE
    if vendor_lz4.exists():
        return vendor_lz4
    return tool_asset(tool_root, BIN_DIR, LZ4_EXE)


def default_hook_script(tool_root: Path) -> Path:
    return tool_asset(tool_root, DEFAULT_TEMPLATE)


def package_hook_script(tool_root: Path, package: str) -> Path:
    return tool_asset(tool_root, package, DEFAULT_TEMPLATE)


def bypass_script(tool_root: Path, name: str) -> Path:
    return tool_asset(tool_root, BYPASS_DIR, f"bypass_{name}.js")


def package_logs_dir(tool_root: Path, package: str) -> Path:
    return tool_asset(tool_root, package, "logs")
