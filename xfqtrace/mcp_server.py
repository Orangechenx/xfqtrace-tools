from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import anyio.lowlevel
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server import Server
from mcp.types import CallToolResult, JSONRPCMessage, TextContent, Tool
from mcp.shared.message import SessionMessage

from .config import package_logs_dir
from .core import XfqtraceCore, XfqtraceError


@asynccontextmanager
async def dual_stdio_server():
    """自定义 stdio 传输层，同时支持 Content-Length 和 JSON Lines 两种格式。

    Content-Length 格式 (标准 MCP, Claude Desktop):
        Content-Length: N\r\n\r\n{json_body}

    JSON Lines 格式 (Python SDK 原生):
        {json_body}\n

    自动检测客户端首次消息的格式，并以相同格式响应。
    """

    read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

    # 记录客户端首次消息格式（list 包裹以便在闭包中修改）
    _input_format: list[str | None] = [None]

    async def _read_binary_line() -> bytes:
        """从 stdin.buffer 读一行（含换行符）。"""
        return await anyio.to_thread.run_sync(sys.stdin.buffer.readline)

    async def _read_binary_exact(n: int) -> bytes:
        """从 stdin.buffer 读精确 n 个字节。"""
        return await anyio.to_thread.run_sync(lambda: sys.stdin.buffer.read(n))

    async def _write_binary(data: bytes) -> None:
        """写入 stdout.buffer 并 flush。"""
        await anyio.to_thread.run_sync(lambda: sys.stdout.buffer.write(data))
        await anyio.to_thread.run_sync(sys.stdout.buffer.flush)

    async def stdin_reader():
        try:
            async with read_stream_writer:
                while True:
                    raw_line = await _read_binary_line()
                    if not raw_line:
                        break
                    line = raw_line.decode("utf-8").rstrip("\r\n")

                    fmt = _input_format[0]
                    if fmt is None:
                        if line.lower().startswith("content-length:"):
                            _input_format[0] = "content_length"
                        else:
                            _input_format[0] = "json_lines"
                    fmt = _input_format[0]

                    if fmt == "content_length" and line.lower().startswith("content-length:"):
                        cl = int(line.split(":", 1)[1].strip())
                        # 读空行
                        await _read_binary_line()
                        # 读 JSON body
                        body_bytes = await _read_binary_exact(cl)
                        body = body_bytes.decode("utf-8")
                    else:
                        body = line

                    if body.strip():
                        try:
                            message = JSONRPCMessage.model_validate_json(body)
                            session_message = SessionMessage(message)
                            await read_stream_writer.send(session_message)
                        except Exception:
                            continue
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()
        except Exception:
            pass

    async def stdout_writer():
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    json_str = session_message.message.model_dump_json(
                        by_alias=True, exclude_none=True,
                    )
                    fmt = _input_format[0]
                    if fmt == "json_lines":
                        data = (json_str + "\n").encode("utf-8")
                    else:
                        body_bytes = json_str.encode("utf-8")
                        data = (
                            f"Content-Length: {len(body_bytes)}\r\n\r\n".encode("utf-8")
                            + body_bytes
                        )
                    await _write_binary(data)
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()
        except Exception:
            pass

    async with anyio.create_task_group() as tg:
        tg.start_soon(stdin_reader)
        tg.start_soon(stdout_writer)
        yield read_stream, write_stream


class XfqtraceMcpServer:
    """MCP Server — 通过官方 mcp SDK 暴露 xfqtrace 能力。"""

    def __init__(self, core: XfqtraceCore) -> None:
        self.core = core
        self.server = Server("xfqtrace-mcp")
        self._analysis_source_cache: dict[tuple[str, str, int], list[Path]] = {}

    def serve(self) -> None:
        self._register_tools()
        import asyncio
        asyncio.run(self._run())

    async def _run(self) -> None:
        async with dual_stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())

    # ── tools 注册 ──────────────────────────────────────────────

    def _register_tools(self) -> None:
        s = self.server

        @s.list_tools()
        async def list_tools() -> list[Tool]:
            return self._tool_definitions()

        @s.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
            return await self._dispatch(name, arguments)

    def _tool_definitions(self) -> list[Tool]:
        return [
            Tool(
                name="xfqtrace_info",
                description="检查 xfQTrace 工具目录、核心资产和本机 adb/frida/python 可用性。",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="xfqtrace_doctor",
                description="检查设备连接、frida-server 状态、资产完整性。",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="xfqtrace_generate_config",
                description="生成包级半自动化 trace Frida 脚本，写入 <package>/半自动化trace.js。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "package": {"type": "string", "description": "目标包名"},
                        "so_name": {"type": "string", "description": "目标 SO 名"},
                        "offset": {"type": ["string", "integer"], "description": "函数 RVA（支持 0x 前缀）"},
                        "hook_args": {"type": "string", "default": "env,obj"},
                        "hook_ret": {"type": "string", "default": "hex"},
                        "max_traces": {"type": "integer", "default": 1},
                        "output_path": {"type": "string"},
                        "overwrite": {"type": "boolean", "default": False},
                        "out_format": {"type": "string", "default": "traceui"},
                        "inline_hook_backend": {"type": "integer", "default": 2},
                        "lz4_enable": {"type": "boolean", "default": True},
                        "lz4_level": {"type": "integer", "default": 0},
                        "sync_flush": {"type": "boolean", "default": False},
                        "anon_trace": {"type": "boolean", "default": False},
                        "arg_filter_idx": {"type": "integer"},
                        "arg_filter_value": {"type": "string"},
                        "memory_trace": {"type": "boolean"},
                    },
                    "required": ["package", "so_name", "offset"],
                },
            ),
            Tool(
                name="xfqtrace_run",
                description="构建或执行全自动 trace；默认 dry-run，execute=true 才实际执行。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "attach": {"type": "boolean", "default": False},
                        "hook_script": {"type": "string"},
                        "bypass": {"type": "string", "description": "逗号分隔的 bypass 名称"},
                        "timeout": {"type": "integer", "default": 120},
                        "execute": {"type": "boolean", "default": False},
                        "serial": {"type": "string"},
                        "tool_root": {"type": "string", "description": "原始工具目录路径"},
                    },
                    "required": ["package"],
                },
            ),
            Tool(
                name="xfqtrace_list_logs",
                description="列出指定包名的本地 logs 记录。",
                inputSchema={
                    "type": "object",
                    "properties": {"package": {"type": "string"}},
                    "required": ["package"],
                },
            ),
            Tool(
                name="xfqtrace_preview_log",
                description="读取指定包最新或指定 run 的 trace 日志片段。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "run_id": {"type": "string"},
                        "relative_path": {"type": "string"},
                        "max_bytes": {"type": "integer", "default": 8192},
                    },
                    "required": ["package"],
                },
            ),
            Tool(
                name="xfqtrace_logcat_command",
                description="生成 xfQTrace logcat 监控命令。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "serial": {"type": "string"},
                        "clear": {"type": "boolean", "default": False},
                        "tag": {"type": "string", "default": "xfQTrace:D"},
                    },
                },
            ),
            Tool(
                name="xfqtrace_summarize",
                description="分析 trace 摘要，识别 XOR 循环、连续内存访问等模式。",
                inputSchema=self._analysis_schema(),
            ),
            Tool(
                name="xfqtrace_stack",
                description="基于 hook call/ret 记录重建调用栈。",
                inputSchema={
                    **self._analysis_schema(),
                    "properties": {
                        **self._analysis_schema()["properties"],
                        "max_depth": {"type": "integer", "default": 20},
                    },
                },
            ),
            Tool(
                name="xfqtrace_grep",
                description="结构化查询 trace 指令，支持 PC 范围、opcode、module 和寄存器值过滤。",
                inputSchema={
                    **self._analysis_schema(),
                    "properties": {
                        **self._analysis_schema()["properties"],
                        "pc_range": {"type": "string", "description": "0xstart-0xend"},
                        "opcode": {"type": "string"},
                        "module": {"type": "string"},
                        "reg": {"type": "string", "description": "reg=value，如 x0=0x1234"},
                        "max_results": {"type": "integer", "default": 50},
                    },
                },
            ),
            Tool(
                name="xfqtrace_search_sequence",
                description="搜索指令序列，seq 使用分号分隔，支持相邻/非相邻模式和 *、? wildcard。",
                inputSchema={
                    **self._analysis_schema(),
                    "properties": {
                        **self._analysis_schema()["properties"],
                        "seq": {"type": "string", "description": "如: ldr x0, *; bl strcmp"},
                        "pc_range": {"type": "string", "description": "0xstart-0xend"},
                        "module": {"type": "string"},
                        "opcode": {"type": "string"},
                        "context": {"type": "integer", "default": 0},
                        "adjacent": {"type": "boolean", "default": True},
                        "max_gap": {"type": "integer", "default": 0, "description": "非相邻模式下两条匹配指令之间允许跨过的最大指令数，0 表示不限制"},
                        "max_results": {"type": "integer", "default": 50},
                    },
                    "required": ["seq"],
                },
            ),
            Tool(
                name="xfqtrace_stats",
                description="统计 trace 中的 hook 调用次数和指令 opcode 分布。",
                inputSchema=self._analysis_schema(),
            ),
            Tool(
                name="xfqtrace_regdiff",
                description="统计寄存器变化次数、首次/末次/最大/最小值。",
                inputSchema={
                    **self._analysis_schema(),
                    "properties": {
                        **self._analysis_schema()["properties"],
                        "regs": {"type": "array", "items": {"type": "string"}},
                    },
                },
            ),
            Tool(
                name="xfqtrace_mempat",
                description="检测连续内存读写模式。",
                inputSchema=self._analysis_schema(),
            ),
            Tool(
                name="xfqtrace_branch",
                description="分析条件分支命中率，并统计 br/blr 间接跳转。",
                inputSchema=self._analysis_schema(),
            ),
            Tool(
                name="xfqtrace_taint",
                description="执行轻量污点分析，标记寄存器或内存范围并跟踪传播。",
                inputSchema={
                    **self._analysis_schema(),
                    "properties": {
                        **self._analysis_schema()["properties"],
                        "taint_regs": {"type": "array", "items": {"type": "string"}},
                        "taint_mem_range": {"type": "string", "description": "0xstart-0xend"},
                        "summary": {"type": "boolean", "default": False},
                    },
                },
            ),
            Tool(
                name="xfqtrace_diff",
                description="对比两个 trace 的覆盖差异、opcode/module 分布和首个顺序分歧。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "left": {"type": "string", "description": "左侧 trace 文件路径"},
                        "right": {"type": "string", "description": "右侧 trace 文件路径"},
                        "left_text": {"type": "string", "description": "左侧 trace 文本"},
                        "right_text": {"type": "string", "description": "右侧 trace 文本"},
                        "max_samples": {"type": "integer", "default": 20},
                        "ignore_operands": {"type": "boolean", "default": False},
                        "include_calls": {"type": "boolean", "default": False},
                    },
                },
            ),
            Tool(
                name="xfqtrace_index",
                description="将 trace 日志导入 SQLite 索引库，便于后续高效查询。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "input": {"type": "string", "description": "trace 日志文件路径，支持 .log / .log.lz4"},
                        "db": {"type": "string", "description": "输出 SQLite 索引库路径"},
                        "replace": {"type": "boolean", "default": False},
                    },
                    "required": ["input"],
                },
            ),
            Tool(
                name="xfqtrace_query",
                description="对 SQLite 索引库执行只读 SELECT/CTE 查询。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "db": {"type": "string", "description": "SQLite 索引库路径"},
                        "sql": {"type": "string", "description": "只读 SELECT SQL"},
                        "limit": {"type": "integer", "default": 200},
                    },
                    "required": ["db", "sql"],
                },
            ),
            Tool(
                name="xfqtrace_query_reg",
                description="按寄存器访问查询索引库中的指令。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "db": {"type": "string", "description": "SQLite 索引库路径"},
                        "write": {"type": "string", "description": "查询写入/变化的寄存器，如 x0"},
                        "reg": {"type": "string", "description": "查询未变化访问的寄存器"},
                        "max_results": {"type": "integer", "default": 50},
                    },
                    "required": ["db"],
                },
            ),
            Tool(
                name="xfqtrace_query_op",
                description="按 opcode 和可选模块名查询索引库中的指令。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "db": {"type": "string", "description": "SQLite 索引库路径"},
                        "opcode": {"type": "string", "description": "opcode，如 bl / str / ldr"},
                        "module": {"type": "string", "description": "模块名过滤"},
                        "max_results": {"type": "integer", "default": 50},
                    },
                    "required": ["db", "opcode"],
                },
            ),
            Tool(
                name="xfqtrace_query_sequence",
                description="基于 SQLite 索引搜索相邻指令序列。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "db": {"type": "string", "description": "SQLite 索引库路径"},
                        "seq": {"type": "string", "description": "相邻指令序列，分号分隔"},
                        "context": {"type": "integer", "default": 0},
                        "max_results": {"type": "integer", "default": 50},
                    },
                    "required": ["db", "seq"],
                },
            ),
        ]

    async def _dispatch(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        try:
            if name == "xfqtrace_info":
                result = self.core.info()
            elif name == "xfqtrace_doctor":
                result = self.core.doctor()
            elif name == "xfqtrace_generate_config":
                result = self.core.generate_config(**self._extract_gen_args(arguments))
            elif name == "xfqtrace_run":
                result = self._handle_run(arguments, self.core)
            elif name == "xfqtrace_list_logs":
                result = self.core.list_logs(package=str(arguments.get("package", "")))
            elif name == "xfqtrace_preview_log":
                result = self.core.preview_log(
                    package=str(arguments.get("package", "")),
                    run_id=arguments.get("run_id"),
                    relative_path=arguments.get("relative_path"),
                    max_bytes=int(arguments.get("max_bytes", 8192)),
                )
            elif name == "xfqtrace_logcat_command":
                result = self.core.logcat_command(
                    serial=arguments.get("serial"),
                    clear=bool(arguments.get("clear", False)),
                    tag=str(arguments.get("tag", "xfQTrace:D")),
                )
            elif name == "xfqtrace_summarize":
                from .analyzer import summarize
                result = summarize(**self._analysis_source(arguments))
            elif name == "xfqtrace_stack":
                from .analyzer import build_stack
                result = {
                    "calls": build_stack(
                        **self._analysis_source(arguments),
                        max_depth=int(arguments.get("max_depth", 20)),
                    )
                }
                result["count"] = len(result["calls"])
            elif name == "xfqtrace_grep":
                from .analyzer import grep, parse_reg_condition
                reg_arg = arguments.get("reg")
                result = {
                    "results": grep(
                        **self._analysis_source(arguments),
                        pc_range=self._parse_range(arguments.get("pc_range")),
                        opcode=arguments.get("opcode"),
                        module=arguments.get("module"),
                        reg_filter=self._parse_reg_filter(reg_arg) if isinstance(reg_arg, dict) else None,
                        reg_conditions=[parse_reg_condition(str(reg_arg))] if reg_arg and not isinstance(reg_arg, dict) else None,
                        max_results=int(arguments.get("max_results", 50)),
                    )
                }
                result["matches"] = len(result["results"])
            elif name == "xfqtrace_search_sequence":
                from .analyzer import search_sequence
                result = {
                    "results": search_sequence(
                        **self._analysis_source(arguments),
                        pattern=str(arguments.get("seq", "")),
                        pc_range=self._parse_range(arguments.get("pc_range")),
                        module=arguments.get("module"),
                        opcode=arguments.get("opcode"),
                        context=int(arguments.get("context", 0)),
                        adjacent=bool(arguments.get("adjacent", True)),
                        max_gap=int(arguments.get("max_gap", 0)),
                        max_results=int(arguments.get("max_results", 50)),
                    )
                }
                result["matches"] = len(result["results"])
            elif name == "xfqtrace_stats":
                from .analyzer import stats
                result = stats(**self._analysis_source(arguments))
            elif name == "xfqtrace_regdiff":
                from .analyzer import regdiff
                regs = arguments.get("regs")
                result = {
                    "registers": regdiff(
                        **self._analysis_source(arguments),
                        target_regs=list(regs) if isinstance(regs, list) else None,
                    )
                }
            elif name == "xfqtrace_mempat":
                from .analyzer import mempat
                result = {"patterns": mempat(**self._analysis_source(arguments))}
            elif name == "xfqtrace_branch":
                from .analyzer import branch_analysis
                result = {"branches": branch_analysis(**self._analysis_source(arguments))}
            elif name == "xfqtrace_taint":
                from .analyzer import taint_analysis
                result = taint_analysis(
                    **self._analysis_source(arguments),
                    taint_regs=self._string_list(arguments.get("taint_regs")),
                    taint_mem_range=self._parse_range(arguments.get("taint_mem_range")),
                    summary=bool(arguments.get("summary", False)),
                )
            elif name == "xfqtrace_diff":
                from .trace_diff import diff_traces
                result = diff_traces(
                    left=arguments.get("left"),
                    right=arguments.get("right"),
                    left_text=arguments.get("left_text"),
                    right_text=arguments.get("right_text"),
                    max_samples=int(arguments.get("max_samples", 20)),
                    ignore_operands=bool(arguments.get("ignore_operands", False)),
                    include_calls=bool(arguments.get("include_calls", False)),
                )
            elif name == "xfqtrace_index":
                from .trace_index import index_trace
                input_path = str(arguments.get("input") or "").strip()
                if not input_path:
                    raise XfqtraceError("必须提供 input")
                result = index_trace(
                    input_path,
                    db_path=arguments.get("db"),
                    replace=bool(arguments.get("replace", False)),
                )
            elif name == "xfqtrace_query":
                from .trace_index import query_sql
                db_path = str(arguments.get("db") or "").strip()
                sql = str(arguments.get("sql") or "").strip()
                if not db_path or not sql:
                    raise XfqtraceError("必须提供 db 和 sql")
                rows = query_sql(db_path, sql, limit=int(arguments.get("limit", 200)))
                result = {"matches": len(rows), "rows": rows}
            elif name == "xfqtrace_query_reg":
                from .trace_index import query_reg
                db_path = str(arguments.get("db") or "").strip()
                if not db_path:
                    raise XfqtraceError("必须提供 db")
                rows = query_reg(
                    db_path,
                    write=arguments.get("write"),
                    reg=arguments.get("reg"),
                    limit=int(arguments.get("max_results", 50)),
                )
                result = {"matches": len(rows), "results": rows}
            elif name == "xfqtrace_query_op":
                from .trace_index import query_op
                db_path = str(arguments.get("db") or "").strip()
                opcode = str(arguments.get("opcode") or "").strip()
                if not db_path or not opcode:
                    raise XfqtraceError("必须提供 db 和 opcode")
                rows = query_op(
                    db_path,
                    opcode=opcode,
                    module=arguments.get("module"),
                    limit=int(arguments.get("max_results", 50)),
                )
                result = {"matches": len(rows), "results": rows}
            elif name == "xfqtrace_query_sequence":
                from .trace_index import query_sequence
                db_path = str(arguments.get("db") or "").strip()
                seq = str(arguments.get("seq") or "").strip()
                if not db_path or not seq:
                    raise XfqtraceError("必须提供 db 和 seq")
                rows = query_sequence(
                    db_path,
                    seq,
                    context=int(arguments.get("context", 0)),
                    limit=int(arguments.get("max_results", 50)),
                )
                result = {"matches": len(rows), "results": rows}
            else:
                raise XfqtraceError(f"未知工具: {name}")

            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
            )
        except XfqtraceError as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True,
            )
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"执行失败: {e}")],
                isError=True,
            )

    @staticmethod
    def _analysis_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "input": {"type": "string", "description": "trace 文件路径或包名"},
                "package": {"type": "string", "description": "目标包名，未传 input 时使用"},
                "text": {"type": "string", "description": "直接传入 trace 文本"},
                "log_dir": {"type": "string", "description": "日志目录"},
                "run_id": {"type": "string", "description": "logs 下的运行编号"},
                "relative_path": {"type": "string", "description": "run 目录内的 trace 相对路径"},
            },
        }

    def _analysis_source(self, a: dict[str, Any]) -> dict[str, Any]:
        text = a.get("text")
        if text is not None:
            return {"text": str(text)}

        source = str(a.get("input") or a.get("package") or "").strip()
        if not source:
            raise XfqtraceError("必须提供 input/package 或 text")

        path = Path(source).expanduser()
        if path.exists():
            if path.is_dir():
                raise XfqtraceError(f"路径是目录，不是 trace 文件: {source}")
            return {"paths": [path.resolve()]}

        log_dir = a.get("log_dir")
        resolved_log_dir = Path(str(log_dir)).expanduser() if log_dir else package_logs_dir(self.core.tool_root, source)
        run_id = str(a.get("run_id") or "").strip()
        if run_id:
            return {"paths": [self._resolve_run_trace(resolved_log_dir, run_id, a.get("relative_path"))]}
        return {"paths": self._resolve_package_trace_cached(source, resolved_log_dir)}

    def _resolve_package_trace_cached(self, package: str, log_dir: Path) -> list[Path]:
        """缓存包名到最新 trace 的解析结果，避免 MCP 连续查询重复扫描目录。"""
        resolved_log_dir = log_dir.resolve()
        cache_token = self._dir_mtime_ns(resolved_log_dir)
        key = (package, str(resolved_log_dir), cache_token)
        cached = self._analysis_source_cache.get(key)
        if cached is not None:
            return list(cached)

        stale_prefix = (package, str(resolved_log_dir))
        for stale_key in list(self._analysis_source_cache):
            if stale_key[:2] == stale_prefix:
                del self._analysis_source_cache[stale_key]

        from .analyzer import resolve_trace_file
        paths = resolve_trace_file(package, resolved_log_dir)
        self._analysis_source_cache[key] = list(paths)
        return list(paths)

    @staticmethod
    def _dir_mtime_ns(path: Path) -> int:
        try:
            return path.stat().st_mtime_ns
        except OSError:
            return -1

    @staticmethod
    def _resolve_run_trace(log_dir: Path, run_id: str, relative_path: Any = None) -> Path:
        run_dir = (log_dir / run_id).resolve()
        if not run_dir.exists() or not run_dir.is_dir():
            raise XfqtraceError(f"run_id 不存在: {run_id}")

        if relative_path:
            target = (run_dir / str(relative_path)).resolve()
            if target != run_dir and run_dir not in target.parents:
                raise XfqtraceError(f"relative_path 越界: {relative_path}")
            if not target.exists() or not target.is_file():
                raise XfqtraceError(f"trace 文件不存在: {relative_path}")
            return target

        files = sorted(
            [f for f in run_dir.rglob("*") if f.is_file() and not f.name.endswith(".lz4") and f.stat().st_size > 0],
            key=lambda x: x.stat().st_size,
            reverse=True,
        )
        if files:
            return files[0]

        lz4_files = sorted(
            [f for f in run_dir.rglob("*.lz4") if f.is_file() and f.stat().st_size > 0],
            key=lambda x: x.stat().st_size,
            reverse=True,
        )
        if lz4_files:
            return lz4_files[0]

        raise XfqtraceError(f"run 目录下无可用 trace 文件: {run_dir}")

    @staticmethod
    def _parse_range(value: Any) -> tuple[int, int] | None:
        if value in (None, ""):
            return None
        if isinstance(value, (list, tuple)) and len(value) == 2:
            start = int(value[0], 0) if isinstance(value[0], str) else int(value[0])
            end = int(value[1], 0) if isinstance(value[1], str) else int(value[1])
        else:
            parts = str(value).split("-")
            if len(parts) != 2:
                raise XfqtraceError("地址范围格式错误，应为 0xstart-0xend")
            start = int(parts[0].strip(), 0)
            end = int(parts[1].strip(), 0)
        if start > end:
            raise XfqtraceError(f"地址范围起始地址不能大于结束地址: {hex(start)} > {hex(end)}")
        return start, end

    @staticmethod
    def _parse_reg_filter(value: Any) -> dict[str, int] | None:
        if value in (None, ""):
            return None
        if isinstance(value, dict):
            return {
                str(reg): int(raw, 0) if isinstance(raw, str) else int(raw)
                for reg, raw in value.items()
            }
        raw = str(value)
        if "=" not in raw:
            raise XfqtraceError("reg 格式错误，应为 reg=value 如 x0=0x1234")
        reg, val = raw.split("=", 1)
        return {reg.strip(): int(val.strip(), 0)}

    @staticmethod
    def _string_list(value: Any) -> list[str] | None:
        if value in (None, ""):
            return None
        if isinstance(value, list):
            return [str(v) for v in value if str(v).strip()]
        return [v.strip() for v in str(value).split(",") if v.strip()]

    @staticmethod
    def _extract_gen_args(a: dict[str, Any]) -> dict[str, Any]:
        return {
            "package": str(a.get("package", "")),
            "so_name": str(a.get("so_name", "")),
            "offset": a.get("offset", ""),
            "hook_args": str(a.get("hook_args", "env,obj")),
            "hook_ret": str(a.get("hook_ret", "hex")),
            "max_traces": int(a.get("max_traces", 1)),
            "output_path": a.get("output_path"),
            "overwrite": bool(a.get("overwrite", False)),
            "out_format": str(a.get("out_format", "traceui")),
            "inline_hook_backend": int(a.get("inline_hook_backend", 2)),
            "lz4_enable": bool(a.get("lz4_enable", True)),
            "lz4_level": int(a.get("lz4_level", 0)),
            "sync_flush": bool(a.get("sync_flush", False)),
            "anon_trace": bool(a.get("anon_trace", False)),
            "arg_filter_idx": a.get("arg_filter_idx"),
            "arg_filter_value": a.get("arg_filter_value"),
            "memory_trace": a.get("memory_trace"),
        }

    @staticmethod
    def _handle_run(a: dict[str, Any], core: XfqtraceCore | None = None) -> dict[str, Any]:
        """处理 MCP xfqtrace_run 请求。"""
        pkg = str(a.get("package", ""))
        attach = bool(a.get("attach", False))
        hook_script = a.get("hook_script")
        timeout = int(a.get("timeout", 120))
        execute = bool(a.get("execute", False))
        serial = a.get("serial")
        tool_root = a.get("tool_root")
        bypass_raw = a.get("bypass")
        bypass = [b.strip() for b in bypass_raw.split(",") if b.strip()] if bypass_raw else None

        if not execute or core is None:
            return {
                "executed": False,
                "plan": {
                    "package": pkg,
                    "attach": attach,
                    "hook_script": hook_script,
                    "timeout": timeout,
                    "execute": execute,
                    "bypass": bypass,
                    "serial": serial,
                    "tool_root": tool_root,
                },
            }

        # 如果指定了 tool_root，重建 core
        if tool_root or serial:
            from .core import XfqtraceCore as Core
            run_core = Core(tool_root=tool_root, serial=serial or core.device.serial)
        else:
            run_core = core

        # 真实执行
        return run_core.run(
            package=pkg,
            attach=attach,
            hook_script=hook_script,
            bypass=bypass,
            timeout=timeout,
            execute=True,
        )
