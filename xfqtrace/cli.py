from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from .core import XfqtraceCore, XfqtraceError

app = typer.Typer(
    name="xfqtrace",
    help="真机 Android NDK 指令级 trace — CLI + MCP",
    no_args_is_help=True,
)

# 全局共享的 core 实例（按需懒初始化）
_core: XfqtraceCore | None = None


def get_core(
    tool_root: str | None = None,
    serial: str | None = None,
) -> XfqtraceCore:
    global _core
    if _core is None:
        _core = XfqtraceCore(tool_root=tool_root, serial=serial)
    elif tool_root or serial:
        # 如果显式传了参数则重新创建
        _core = XfqtraceCore(tool_root=tool_root, serial=serial)
    return _core


def print_json(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


# ── doctor ──────────────────────────────────────────────────────

@app.command()
def doctor(
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
    serial: Optional[str] = typer.Option(None, "--serial", "--device", help="ADB 设备序列号"),
):
    """检查环境：adb、frida、frida-server、资产完整性。"""
    try:
        core = get_core(tool_root=tool_root, serial=serial)
        result = core.doctor()
        print_json(result)
    except XfqtraceError as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── info ────────────────────────────────────────────────────────

@app.command()
def info(
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
):
    """查看工具资产信息。"""
    core = get_core(tool_root=tool_root)
    print_json(core.info())


# ── gen-config ──────────────────────────────────────────────────

@app.command()
def gen_config(
    package: str = typer.Option(..., "-p", "--package", help="目标包名"),
    so_name: str = typer.Option(..., "--so", "--so-name", help="目标 SO 名"),
    offset: str = typer.Option(..., "--offset", help="函数 RVA（支持 0x 十六进制）"),
    hook_args: str = typer.Option("env,obj", "--hook-args", help="hook_format.args"),
    hook_ret: str = typer.Option("hex", "--hook-ret", help="hook_format.ret"),
    max_traces: int = typer.Option(1, "--max-traces", help="trace 次数上限"),
    output_path: Optional[str] = typer.Option(None, "--output", help="输出路径（默认写入 <package>/半自动化trace.js）"),
    overwrite: bool = typer.Option(False, "--overwrite", help="覆盖已有文件"),
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
    out_format: str = typer.Option("traceui", "--out-format", help="输出格式"),
    inline_hook_backend: int = typer.Option(2, "--inline-hook-backend", help="0=ShadowHook, 1=frida-gum, 2=Dobby"),
    no_lz4: bool = typer.Option(False, "--no-lz4", help="关闭 LZ4 压缩"),
    lz4_level: int = typer.Option(0, "--lz4-level", help="LZ4 压缩等级"),
    sync_flush: bool = typer.Option(False, "--sync-flush", help="同步刷盘（排查崩溃用）"),
    anon_trace: bool = typer.Option(False, "--anon-trace", help="启用匿名段 trace"),
    arg_filter_idx: Optional[int] = typer.Option(None, "--arg-filter-idx", help="参数过滤索引"),
    arg_filter_value: Optional[str] = typer.Option(None, "--arg-filter-value", help="参数过滤目标值"),
    memory_trace: Optional[bool] = typer.Option(None, "--memory-trace/--no-memory-trace", help="内存 trace"),
):
    """生成包级半自动化 trace Frida 脚本。"""
    try:
        core = get_core(tool_root=tool_root)
        result = core.generate_config(
            package=package,
            so_name=so_name,
            offset=offset,
            hook_args=hook_args,
            hook_ret=hook_ret,
            max_traces=max_traces,
            output_path=output_path,
            overwrite=overwrite,
            out_format=out_format,
            inline_hook_backend=inline_hook_backend,
            lz4_enable=not no_lz4,
            lz4_level=lz4_level,
            sync_flush=sync_flush,
            anon_trace=anon_trace,
            arg_filter_idx=arg_filter_idx,
            arg_filter_value=arg_filter_value,
            memory_trace=memory_trace,
        )
        print_json(result)
    except XfqtraceError as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── run ─────────────────────────────────────────────────────────

@app.command()
def run(
    package: str = typer.Option(..., "-p", "--package", help="目标包名"),
    attach: bool = typer.Option(False, "--attach", help="附加到已运行的进程"),
    hook_script: Optional[str] = typer.Option(None, "--script", help="自定义 Frida JS 脚本路径"),
    so_path: Optional[str] = typer.Option(None, "--so-path", help="libxfqtrace.so 路径（默认搜索工具目录 bin/）"),
    bypass: Optional[str] = typer.Option(None, "--bypass", help="bypass 名称，逗号分隔"),
    timeout: int = typer.Option(120, "--timeout", help="frida 超时时间（秒）"),
    execute: bool = typer.Option(False, "--execute", help="真实执行，默认 dry-run 输出计划"),
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
    serial: Optional[str] = typer.Option(None, "--serial", "--device", help="ADB 设备序列号"),
):
    """构建或执行全自动 trace（默认 dry-run）。"""
    try:
        core = get_core(tool_root=tool_root, serial=serial)
        bypass_list = [b.strip() for b in bypass.split(",") if b.strip()] if bypass else None
        result = core.run(
            package=package,
            attach=attach,
            hook_script=hook_script,
            so_path=so_path,
            bypass=bypass_list,
            timeout=timeout,
            execute=execute,
        )
        print_json(result)
    except XfqtraceError as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)
    except Exception as e:
        print(f"运行异常: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── pull-only ───────────────────────────────────────────────────

@app.command(name="pull-only")
def pull_only(
    package: str = typer.Option(..., "-p", "--package", help="目标包名"),
    execute: bool = typer.Option(False, "--execute", help="真实执行拉取"),
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
    serial: Optional[str] = typer.Option(None, "--serial", "--device", help="ADB 设备序列号"),
):
    """仅从设备拉取 trace 日志并解压。"""
    try:
        core = get_core(tool_root=tool_root, serial=serial)
        if not execute:
            print_json({"executed": False, "package": package})
            return
        core.device.resolve_serial()
        result = core.device.pull_logs(package)
        print_json(result)
    except XfqtraceError as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── list-logs ───────────────────────────────────────────────────

@app.command(name="list-logs")
def list_logs(
    package: str = typer.Option(..., "-p", "--package", help="目标包名"),
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
):
    """列出本地 trace 日志。"""
    core = get_core(tool_root=tool_root)
    print_json(core.list_logs(package))


# ── preview-log ─────────────────────────────────────────────────

@app.command(name="preview-log")
def preview_log(
    package: str = typer.Option(..., "-p", "--package", help="目标包名"),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="logs 下的运行编号"),
    relative_path: Optional[str] = typer.Option(None, "--relative-path", help="run 目录内相对路径"),
    max_bytes: int = typer.Option(8192, "--max-bytes", help="最大读取字节数"),
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
):
    """预览 trace 日志文件。"""
    try:
        core = get_core(tool_root=tool_root)
        print_json(core.preview_log(
            package=package,
            run_id=run_id,
            relative_path=relative_path,
            max_bytes=max_bytes,
        ))
    except XfqtraceError as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── logcat ──────────────────────────────────────────────────────

@app.command()
def logcat(
    serial: Optional[str] = typer.Option(None, "--serial", "--device", help="ADB 设备序列号"),
    clear: bool = typer.Option(False, "--clear", help="生成清空 logcat 命令"),
    tag: str = typer.Option("xfQTrace:D", "--tag", help="logcat tag 过滤"),
):
    """生成 xfQTrace logcat 监控命令。"""
    core = get_core(serial=serial)
    print_json(core.logcat_command(serial=serial, clear=clear, tag=tag))


# ── install ─────────────────────────────────────────────────────

@app.command()
def install():
    """将 xfq / xfqtrace 注册到 ~/.local/bin（创建软链接）。"""
    import os
    import stat
    from pathlib import Path

    # 当前入口点路径
    entry = Path(sys.argv[0]).resolve()
    if not entry.exists() or entry.name not in ("xfqtrace", "xfqtrace.exe"):
        # fallback: 找 venv 下的入口
        entry = Path(__file__).resolve().parents[2] / ".venv-frida162" / "bin" / "xfqtrace"
    if not entry.exists():
        print(f"错误: 未找到入口点（尝试 {entry}）", file=sys.stderr)
        raise typer.Exit(1)

    bindir = Path.home() / ".local" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)

    targets = {
        "xfqtrace": entry,
        "xfq": bindir / "xfqtrace",  # 指向 xfqtrace 的相对链接
    }

    for link_name, link_target in targets.items():
        link_path = bindir / link_name
        if link_path.exists() or link_path.is_symlink():
            link_path.unlink()
        os.symlink(str(link_target), str(link_path))
        # 确保可执行
        mode = os.stat(link_path).st_mode
        os.chmod(link_path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"[+] {link_path} -> {link_target}")

    print()
    print("现在可以直接使用：")
    print("  xfqtrace doctor")
    print("  xfq --help")


# ── add ────────────────────────────────────────────────────────

@app.command()
def add(
    source: Optional[str] = typer.Argument(None, help="libxfqtrace.so 路径，不传则在当前目录查找"),
):
    """将 libxfqtrace.so 复制到包内 _vendor/ 目录，之后 trace 无需 --so-path。

    直接传路径：xfqtrace add /path/to/libxfqtrace.so
    不传则在当前目录查找 libxfqtrace.so。
    """
    import shutil
    from .config import vendor_dir, ENGINE_SO

    dest_dir = vendor_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / ENGINE_SO

    os_environ = __import__("os").environ
    src: Path | None = None

    if source:
        src = Path(source).expanduser().resolve()
    elif os_environ.get("XFQTRACE_SO"):
        src = Path(os_environ["XFQTRACE_SO"]).expanduser().resolve()
    else:
        # 找候选位置
        from .config import PROJECT_ROOT, DEFAULT_TOOL_DIR_NAME
        candidates = [
            Path.cwd() / ENGINE_SO,
            PROJECT_ROOT / DEFAULT_TOOL_DIR_NAME / "bin" / ENGINE_SO,
        ]
        for c in candidates:
            if c.exists():
                src = c
                break

    if not src or not src.exists():
        print("错误: 未找到 libxfqtrace.so", file=sys.stderr)
        print(f"  用法: xfqtrace add /path/to/libxfqtrace.so", file=sys.stderr)
        print(f"  或将 libxfqtrace.so 放在当前目录下", file=sys.stderr)
        raise typer.Exit(1)

    shutil.copy2(str(src), str(dest))
    size = dest.stat().st_size
    print(f"[+] libxfqtrace.so ({size:,} bytes)")
    print(f"    来源: {src}")
    print(f"    复制到: {dest}")
    print()
    print("现在可以直接执行 trace：")
    print(f"  xfqtrace run -p cn.damai --execute")


# ── mcp ─────────────────────────────────────────────────────────

@app.command()
def mcp(
    tool_root: Optional[str] = typer.Option(None, "--tool-root", help="原始工具目录路径"),
    serial: Optional[str] = typer.Option(None, "--serial", "--device", help="ADB 设备序列号"),
):
    """启动 MCP Server (stdio 模式)。"""
    core = get_core(tool_root=tool_root, serial=serial)
    from .mcp_server import XfqtraceMcpServer
    server = XfqtraceMcpServer(core)
    server.serve()


def main() -> None:
    """提供给 pyproject.toml [project.scripts] 的入口。"""
    app()


if __name__ == "__main__":
    main()
