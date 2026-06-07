from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from typing import Any

import anyio
import anyio.lowlevel
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server import Server
from mcp.types import CallToolResult, JSONRPCMessage, TextContent, Tool
from mcp.shared.message import SessionMessage

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
