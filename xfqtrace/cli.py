from __future__ import annotations

import json
import re
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


# ── 分析命令 ──────────────────────────────────────────────────

TRACE_FILE_HELP = "trace 日志文件路径（不传则自动找指定包的最新日志）"
PKG_OR_FILE_HELP = "包名或 trace 文件路径（不传则自动找最新日志）"


def _resolve_path(package_or_path: str | None, tool_root: str | None, log_dir: str | None) -> list[Path]:
    """统一解析 trace 文件路径。"""
    from pathlib import Path

    if package_or_path and Path(package_or_path).exists():
        p = Path(package_or_path).resolve()
        if p.is_dir():
            raise FileNotFoundError(f"路径是目录，不是 trace 文件: {package_or_path}")
        return [p]

    pkg = package_or_path or ""
    if not pkg:
        from .config import resolve_tool_root
        from .analyzer import resolve_trace_file
        tr = resolve_tool_root(tool_root)
        base = Path(log_dir) if log_dir else tr
        candidates = sorted(
            [d for d in base.rglob("*.log*") if d.is_file() and not d.name.endswith(".lz4")],
            key=lambda x: x.stat().st_mtime, reverse=True,
        )
        if candidates:
            return [candidates[0]]
        raise FileNotFoundError("未找到 trace 日志文件")

    from .analyzer import resolve_trace_file
    return resolve_trace_file(pkg, log_dir)


def _add_json_flag() -> bool:
    """在 typer 上下文中标记 --json，作为默认参数。"""
    return False


# ── summarize ──────────────────────────────────────────────────

@app.command()
def summarize(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """智能摘要 — 识别 XOR 循环、内存拷贝等算法模式。"""
    try:
        from .analyzer import summarize
        paths = _resolve_path(input, tool_root, log_dir)
        result = summarize(paths=paths)

        if json_output:
            print_json(result)
            return

        print(f"指令总数: {result['total_instructions']:,}")
        print(f"指令行数: {result['total_lines']:,}")
        print(f"识别模式: {len(result['patterns'])}")
        for p in result['patterns'][:20]:
            print(f"  ├─ {p['type']}  L{p['start_line']}-L{p['end_line']}")
        if len(result['patterns']) > 20:
            print(f"  ... 还有 {len(result['patterns']) - 20} 个")
        if result['top_opcodes']:
            print(f"\n热门指令 Top 10:")
            for o in result['top_opcodes'][:10]:
                bar = "█" * min(o['count'] // 10, 50)
                print(f"  {o['opcode']:<12} {o['count']:>6}  {bar}")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── stack ──────────────────────────────────────────────────────

@app.command()
def stack(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    max_depth: int = typer.Option(20, "--max-depth"),
    no_collapse: bool = typer.Option(False, "--no-collapse", help="不折叠重复调用"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """调用栈可视化 — 重建函数调用树。"""
    try:
        from .analyzer import build_stack, format_stack_tree
        paths = _resolve_path(input, tool_root, log_dir)
        calls = build_stack(paths=paths, max_depth=max_depth)
        if not calls:
            print("未发现函数调用记录")
            if json_output:
                print_json({"calls": [], "count": 0})
            return
        if json_output:
            print_json({"calls": calls, "count": len(calls)})
            return
        print(format_stack_tree(calls, collapse_repeats=not no_collapse))
        print(f"\n总调用数: {len(calls)}")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── grep ───────────────────────────────────────────────────────

@app.command()
def grep(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    pc_range: Optional[str] = typer.Option(None, "--pc-range", help="PC 范围 0xstart-0xend"),
    opcode: Optional[str] = typer.Option(None, "--opcode", help="指令类型过滤，如 str, ldr, eor"),
    module: Optional[str] = typer.Option(None, "--module", help="模块名过滤"),
    reg: Optional[str] = typer.Option(None, "--reg", help="寄存器条件，如 x0=0x1234"),
    max_results: int = typer.Option(50, "--max", help="最大结果数"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """结构化查询 — 按条件过滤 trace 指令。"""
    try:
        from .analyzer import grep as grep_func
        paths = _resolve_path(input, tool_root, log_dir)

        pc_range_tuple = None
        if pc_range:
            try:
                parts = pc_range.split("-")
                if len(parts) == 2:
                    pc_range_tuple = (int(parts[0], 16), int(parts[1], 16))
                else:
                    raise ValueError
            except ValueError:
                print("错误: --pc-range 格式错误，应为 0xstart-0xend", file=sys.stderr)
                raise typer.Exit(1)

        reg_filter = None
        if reg:
            try:
                if "=" in reg:
                    r, v = reg.split("=", 1)
                    reg_filter = {r: int(v, 16) if v.startswith("0x") else int(v)}
                else:
                    print(f"警告: --reg 缺少 =，忽略过滤 (正确格式: x0=0x1234)", file=sys.stderr)
            except ValueError:
                print("错误: --reg 格式错误，应为 reg=value 如 x0=0x1234", file=sys.stderr)
                raise typer.Exit(1)

        results = grep_func(paths=paths, pc_range=pc_range_tuple, opcode=opcode,
                           module=module, reg_filter=reg_filter, max_results=max_results)
        if json_output:
            print_json({"matches": len(results), "results": results})
            return
        if not results:
            print("未匹配到结果")
            return
        for r in results:
            print(f"  L{r['line_no']:>6} [{r['module']}] {r['address']}!{r['offset']} {r['insn']}")
        print(f"\n匹配 {len(results)} 行")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── slice ──────────────────────────────────────────────────────

@app.command()
def slice(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    output: str = typer.Option("slice_output.log", "--output", help="输出文件路径"),
    pc_range: Optional[str] = typer.Option(None, "--pc-range", help="PC 范围 0xstart-0xend"),
    line_start: int = typer.Option(0, "--line-start", help="起始行号"),
    line_end: int = typer.Option(0, "--line-end", help="结束行号"),
    max_lines: int = typer.Option(0, "--max", help="最大输出行数"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """切片导出 — 裁剪 trace 到指定范围。"""
    try:
        from .analyzer import slice_trace
        paths = _resolve_path(input, None, None)
        if not paths:
            raise FileNotFoundError("未找到 trace 文件")

        pc_range_tuple = None
        if pc_range:
            try:
                parts = pc_range.split("-")
                if len(parts) == 2:
                    pc_range_tuple = (int(parts[0], 16), int(parts[1], 16))
                else:
                    raise ValueError
            except ValueError:
                print("错误: --pc-range 格式错误，应为 0xstart-0xend", file=sys.stderr)
                raise typer.Exit(1)

        line_range = None
        if line_start > 0 and line_end > 0:
            line_range = (line_start, line_end)
        elif line_start > 0:
            line_range = (line_start, 10**9)  # 无上限
        elif line_end > 0:
            line_range = (1, line_end)

        result = slice_trace(paths[0], output, pc_range=pc_range_tuple,
                            line_range=line_range, max_lines=max_lines)
        if json_output:
            print_json(result)
            return
        print(f"切片完成: {result['written_lines']} 行 -> {result['output']}")
        print(f"  总行数: {result['total_lines']}, 匹配写入: {result['written_lines']}, 跳过: {result['skipped_lines']}")
        src_size = result['input_size']
        print(f"  输入大小: {src_size:,} bytes")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── stats ──────────────────────────────────────────────────────

@app.command()
def stats(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """API 调用统计 — 统计函数调用次数和指令分布。"""
    try:
        from .analyzer import stats as stats_func
        paths = _resolve_path(input, tool_root, log_dir)
        result = stats_func(paths=paths)
        if json_output:
            print_json(result)
            return
        print(f"指令总数: {result['total_instructions']:,}")
        print(f"函数调用: {result['total_calls']:,}")
        if result.get("calls"):
            print(f"\n调用分布 (Top {min(10, len(result['calls']))}):")
            for c in result["calls"][:10]:
                bar = "█" * min(c["count"], 50)
                print(f"  {c['name']:<40} {c['count']:>6}  {bar}")
        if result.get("top_opcodes"):
            print(f"\n指令分布 (Top 10):")
            for o in result["top_opcodes"][:10]:
                bar = "█" * min(o['count'] // 10, 50)
                print(f"  {o['opcode']:<12} {o['count']:>6}  {bar}")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── regdiff ────────────────────────────────────────────────────

@app.command()
def regdiff(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    regs: Optional[str] = typer.Option(None, "--regs", help="关注的寄存器，逗号分隔"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """寄存器变化热力图 — 统计每个寄存器的变化情况。"""
    try:
        from .analyzer import regdiff as regdiff_func
        paths = _resolve_path(input, tool_root, log_dir)
        target_regs = [r.strip() for r in regs.split(",") if r.strip()] if regs else None
        results = regdiff_func(paths=paths, target_regs=target_regs)
        if json_output:
            print_json({"registers": results})
            return
        if not results:
            print("未捕获到寄存器变化")
            return
        print(f"{'寄存器':<10} {'变化次数':<10} {'首次值':<20} {'末次值':<20} {'最小值':<20} {'最大值':<20}")
        print("-" * 100)
        for r in results[:20]:
            print(f"{r['register']:<10} {r['changes']:<10} {r['first']:<20} {r['last']:<20} {r['min']:<20} {r['max']:<20}")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── mempat ─────────────────────────────────────────────────────

@app.command()
def mempat(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """内存访问模式检测 — 识别连续内存拷贝 / 置零等。"""
    try:
        from .analyzer import mempat as mempat_func
        paths = _resolve_path(input, tool_root, log_dir)
        results = mempat_func(paths=paths)
        if json_output:
            print_json({"patterns": results})
            return
        if not results:
            print("未发现连续内存访问模式")
            return
        for r in results:
            print(f"  {r['type']:<20} L{r['start_line']:>6}-L{r['end_line']:<6} stride={r['stride']} count={r['count']}")
        print(f"\n共 {len(results)} 个模式")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── branch ─────────────────────────────────────────────────────

@app.command()
def branch(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    threshold: float = typer.Option(0.0, "--min-rate", help="最低跳转率过滤 0-100"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """分支命中率分析 — 统计条件跳转的跳转/不跳转次数。"""
    try:
        from .analyzer import branch_analysis
        paths = _resolve_path(input, tool_root, log_dir)
        results = branch_analysis(paths=paths)
        if json_output:
            print_json({"branches": results})
            return
        if threshold > 0:
            results = [r for r in results if r["taken_ratio"] >= threshold]
        if not results:
            print("未发现条件分支指令")
            return
        print(f"{'模块':<35} {'偏移':<12} {'指令':<25} {'跳转':<8} {'不跳':<8} {'跳转率':<8}")
        print("-" * 100)
        for r in results[:30]:
            print(f"{r['module']:<35} {r['offset']:<12} {r['insn']:<25} {r['taken']:<8} {r['not_taken']:<8} {r['taken_ratio']:<7}%")
        print(f"\n共 {len(results)} 个分支")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


# ── taint ──────────────────────────────────────────────────────

@app.command()
def taint(
    input: Optional[str] = typer.Argument(None, help=PKG_OR_FILE_HELP),
    tool_root: Optional[str] = typer.Option(None, "--tool-root"),
    log_dir: Optional[str] = typer.Option(None, "--log-dir"),
    taint_reg: Optional[list[str]] = typer.Option(None, "--taint", help="初始标记的寄存器，如 x2，可多次使用"),
    taint_mem: Optional[str] = typer.Option(None, "--taint-mem", help="初始标记的内存范围，如 0x7a000000-0x7a000100"),
    summary: bool = typer.Option(False, "--summary", help="只输出结论，不输出详细传播路径"),
    max_prop: int = typer.Option(50, "--max-prop", help="最大显示的传播链条数"),
    json_output: bool = typer.Option(False, "--json", help="以 JSON 格式输出"),
):
    """污点分析 — 标记输入，跟踪数据传播路径。

    在 trace 中标记一个或多个输入（寄存器/内存），自动跟踪哪些后续指令
    和返回值受到了影响。用于快速判断参数是否参与了签名/加密计算。

    示例:
      xfq taint trace.log --taint x2
      xfq taint trace.log --taint x2 --taint x3
      xfq taint trace.log --taint-mem 0x7a000000-0x7a000100
      xfq taint trace.log --taint x2 --summary
    """
    try:
        from .analyzer import taint_analysis, format_taint_result
        paths = _resolve_path(input, tool_root, log_dir)

        regs = taint_reg
        if regs:
            cleaned = []
            for r in regs:
                # 允许 --taint x2=0x41 (=号后忽略) 也允许纯 --taint x2
                bare = r.split("=", 1)[0] if "=" in r else r
                if re.match(r"^[xw]\d+$", bare) or bare == "sp":
                    cleaned.append(bare)
                else:
                    print(f"错误: 无效的寄存器名 '{bare}'，应为 x0~x30/w0~w30/sp", file=sys.stderr)
                    raise typer.Exit(1)
            regs = cleaned

        mem_range = None
        if taint_mem:
            try:
                parts = taint_mem.split("-")
                if len(parts) == 2:
                    mem_range = (int(parts[0], 16), int(parts[1], 16))
                else:
                    print("错误: --taint-mem 格式错误，应为 0xstart-0xend", file=sys.stderr)
                    raise typer.Exit(1)
            except ValueError:
                print("错误: --taint-mem 地址格式错误，需要使用十六进制如 0x7a000000-0x7a000100", file=sys.stderr)
                raise typer.Exit(1)

        if not regs and not mem_range:
            print("错误: 请至少指定 --taint 或 --taint-mem", file=sys.stderr)
            raise typer.Exit(1)

        result = taint_analysis(
            paths=paths,
            taint_regs=regs,
            taint_mem_range=mem_range,
            summary=summary,
        )

        if json_output:
            print_json(result)
            return

        print(format_taint_result(result, max_prop=max_prop))

    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        raise typer.Exit(1)


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
