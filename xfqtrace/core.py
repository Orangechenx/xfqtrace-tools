from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Iterable

from .config import (
    DEFAULT_TEMPLATE,
    resolve_tool_root,
    engine_so_path,
    lz4_exe_path,
    default_hook_script,
    package_hook_script,
    package_logs_dir,
)
from .device import FridaDevice


class XfqtraceError(ValueError):
    """业务异常。"""


def validate_package(package: str) -> str:
    value = str(package).strip()
    if not value:
        raise XfqtraceError("package 不能为空")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(ch not in allowed for ch in value):
        raise XfqtraceError(f"package 包含非法字符: {package!r}")
    return value


def validate_so_name(so_name: str) -> str:
    value = str(so_name).strip()
    if not value:
        raise XfqtraceError("so_name 不能为空")
    if "/" in value or "\\" in value:
        raise XfqtraceError("so_name 不能包含路径分隔符")
    if not value.endswith(".so"):
        raise XfqtraceError("so_name 建议以 .so 结尾")
    return value


def normalize_offset(offset: int | str) -> int:
    if isinstance(offset, bool):
        raise XfqtraceError("offset 不能是布尔值")
    if isinstance(offset, int):
        return offset
    raw = str(offset).strip().lower().replace("_", "")
    if not raw:
        raise XfqtraceError("offset 不能为空")
    base = 16 if raw.startswith("0x") else 10
    try:
        value = int(raw, base)
    except ValueError as exc:
        raise XfqtraceError(f"offset 格式无效: {offset!r}") from exc
    if value < 0:
        raise XfqtraceError("offset 不能为负数")
    return value


def safe_int(value: Any, default: int, min_value: int = 1) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise XfqtraceError(f"整数参数无效: {value!r}") from exc
    if parsed < min_value:
        raise XfqtraceError(f"整数参数不能小于 {min_value}: {value!r}")
    return parsed


# ── 脚本模板 ──────────────────────────────────────────────────

AGENT_TEMPLATE_RUNTIME = r"""// ======================== 脚本逻辑（一般不需要修改） ========================

const ENGINE_PATH = `/data/data/${CONFIG.package}/files/libxfqtrace.so`;

const _dlopen = new NativeFunction(
    Module.findExportByName(null, "dlopen"), "pointer", ["pointer", "int"]
);
const _dlsym = new NativeFunction(
    Module.findExportByName(null, "dlsym"), "pointer", ["pointer", "pointer"]
);

var g_handle = null;
var g_done_callback = null;

function loadEngine() {
    if (g_handle) return;
    g_handle = _dlopen(Memory.allocUtf8String(ENGINE_PATH), 2);
    if (g_handle.isNull()) throw new Error("dlopen failed: " + ENGINE_PATH);
    console.log("[*] engine loaded: " + g_handle);
}

function getApi(name, ret, args) {
    var addr = _dlsym(g_handle, Memory.allocUtf8String(name));
    if (!addr || addr.isNull()) throw new Error(name + " not found");
    return new NativeFunction(addr, ret, args);
}

function buildJson(base) {
    var json = {};
    json.target = Object.assign({}, CONFIG.target, { base: base.toString() });
    json.options = CONFIG.options;
    return JSON.stringify(json);
}

function armTrace() {
    var mod = Process.findModuleByName(CONFIG.target.so_name);
    if (!mod) { console.log("[-] " + CONFIG.target.so_name + " not loaded"); return; }
    console.log("[*] " + CONFIG.target.so_name + " @ " + mod.base);
    loadEngine();

    var configure   = getApi("xfqtrace_configure", "int", ["pointer"]);
    var start       = getApi("xfqtrace_start", "int", []);
    var get_error   = getApi("xfqtrace_get_last_error", "pointer", []);
    var set_done_cb = getApi("xfqtrace_set_done_callback", "void", ["pointer"]);

    var json = buildJson(mod.base);
    console.log("[*] config: " + json);

    var rc = configure(Memory.allocUtf8String(json));
    if (rc !== 0) { console.log("[-] configure failed: " + get_error().readCString()); return; }

    if (start() !== 0) { console.log("[-] start failed: " + get_error().readCString()); return; }
    console.log("[+] trace armed! " + CONFIG.target.so_name + "+0x" + CONFIG.target.offset.toString(16));

    g_done_callback = new NativeCallback(function() {
        send({type: "trace_done"});
    }, "void", []);
    set_done_cb(g_done_callback);
}

var g_armed = false;
var g_dlopen_listener = Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {},
    onLeave: function(retval) {
        if (!g_armed && Process.findModuleByName(CONFIG.target.so_name)) {
            g_armed = true;
            console.log("[*] detected load: " + CONFIG.target.so_name);
            g_dlopen_listener.detach();
            armTrace();
        }
    }
});

rpc.exports = { stop: function() { try { if (g_dlopen_listener) g_dlopen_listener.detach(); } catch(e) {} } };

if (Process.findModuleByName(CONFIG.target.so_name)) {
    console.log("[*] " + CONFIG.target.so_name + " already loaded");
    g_armed = true;
    armTrace();
}
"""


def render_agent_config(
    *,
    package: str,
    so_name: str,
    offset: int,
    hook_args: str = "env,obj",
    hook_ret: str = "hex",
    max_traces: int = 1,
    out_format: str = "traceui",
    inline_hook_backend: int = 2,
    lz4_enable: bool = True,
    lz4_level: int = 0,
    sync_flush: bool = False,
    anon_trace: bool = False,
    arg_filter_idx: int | None = None,
    arg_filter_value: str | None = None,
    memory_trace: bool | None = None,
) -> str:
    pkg = validate_package(package)
    so = validate_so_name(so_name)
    off = normalize_offset(offset)
    max_t = safe_int(max_traces, default=1)

    options: list[str] = [
        f"        inline_hook_backend: {inline_hook_backend},",
        f"        out_format: {json.dumps(out_format)},",
        f"        lz4_compression: {{ enable: {str(lz4_enable).lower()}, level: {lz4_level} }},",
        f"        stop_condition: {{ max_traces: {max_t} }},",
        f"        hook_format: {{ args: {json.dumps(hook_args)}, ret: {json.dumps(hook_ret)}, naming_source: 0, naming_index: 0 }},",
    ]
    if arg_filter_idx is not None and arg_filter_value is not None:
        options.append(f"        arg_filter: {{ idx: {arg_filter_idx}, value: {json.dumps(arg_filter_value)} }},")
    if memory_trace is not None:
        options.append(f"        memory_trace: {str(memory_trace).lower()},")
    if sync_flush:
        options.append("        sync_flush: true,")
    if anon_trace:
        options.append("        anon_trace: true,")

    opts_block = "\n".join(options)
    return f"""// ===== xfQTrace 半自动化 trace 配置 =====
// 由 xfqtrace 生成；通常只改 CONFIG，不修改下面通用逻辑。

const CONFIG = {{
    package: {json.dumps(pkg)},
    target: {{ type: "func", so_name: {json.dumps(so)}, offset: 0x{off:x} }},
    options: {{
{opts_block}
    }},
}};

{AGENT_TEMPLATE_RUNTIME}"""


# ── Core ──────────────────────────────────────────────────────

class XfqtraceCore:
    def __init__(self, tool_root: str | Path | None = None, serial: str | None = None):
        self.tool_root = resolve_tool_root(tool_root)
        self.device = FridaDevice(serial=serial, tool_root=self.tool_root)

    # ── info / doctor ───────────────────────────────────────────

    def info(self) -> dict[str, Any]:
        return {
            "tool_root": str(self.tool_root),
            "exists": self.tool_root.exists(),
            "assets": {
                "engine_so": _file_info(engine_so_path(self.tool_root)),
                "lz4_exe": _file_info(lz4_exe_path(self.tool_root)),
                "default_hook_script": _file_info(default_hook_script(self.tool_root)),
            },
            "examples": self._list_examples(),
            "executables": {
                "python": shutil.which("python3") or "",
                "adb": shutil.which("adb") or "",
                "frida": shutil.which("frida") or "",
            },
        }

    def doctor(self) -> dict[str, Any]:
        """快速环境诊断。"""
        try:
            return self.device.doctor()
        except Exception as exc:
            return {"error": str(exc), "device": {}, "frida": {}, "assets": {}, "tools": {}}

    def _list_examples(self) -> list[str]:
        if not self.tool_root.exists():
            return []
        pkgs: list[str] = []
        for item in self.tool_root.iterdir():
            if item.is_dir() and "." in item.name and not item.name.startswith("USAGE"):
                if (item / DEFAULT_TEMPLATE).exists() or (item / "logs").exists():
                    pkgs.append(item.name)
        return sorted(pkgs)

    # ── generate config ─────────────────────────────────────────

    def generate_config(
        self,
        *,
        package: str,
        so_name: str,
        offset: int | str,
        hook_args: str = "env,obj",
        hook_ret: str = "hex",
        max_traces: int = 1,
        output_path: str | Path | None = None,
        overwrite: bool = False,
        out_format: str = "traceui",
        inline_hook_backend: int = 2,
        lz4_enable: bool = True,
        lz4_level: int = 0,
        sync_flush: bool = False,
        anon_trace: bool = False,
        arg_filter_idx: int | None = None,
        arg_filter_value: str | None = None,
        memory_trace: bool | None = None,
    ) -> dict[str, Any]:
        pkg = validate_package(package)
        so = validate_so_name(so_name)
        off = normalize_offset(offset)

        if output_path:
            target = Path(output_path).expanduser().resolve()
        else:
            target = package_hook_script(self.tool_root, pkg)
        if target.exists() and not overwrite:
            raise XfqtraceError(f"配置文件已存在，若要覆盖请传 overwrite=true: {target}")

        content = render_agent_config(
            package=pkg,
            so_name=so,
            offset=off,
            hook_args=hook_args,
            hook_ret=hook_ret,
            max_traces=safe_int(max_traces, 1),
            out_format=out_format,
            inline_hook_backend=safe_int(inline_hook_backend, 2, 0),
            lz4_enable=bool(lz4_enable),
            lz4_level=int(lz4_level),
            sync_flush=bool(sync_flush),
            anon_trace=bool(anon_trace),
            arg_filter_idx=arg_filter_idx,
            arg_filter_value=arg_filter_value,
            memory_trace=memory_trace,
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {
            "script_path": str(target),
            "package": pkg,
            "so_name": so,
            "offset": off,
            "offset_hex": f"0x{off:x}",
            "overwritten": overwrite,
        }

    # ── run trace ───────────────────────────────────────────────

    def run(
        self,
        *,
        package: str,
        attach: bool = False,
        hook_script: str | Path | None = None,
        so_path: str | Path | None = None,
        bypass: list[str] | None = None,
        timeout: int = 120,
        execute: bool = False,
    ) -> dict[str, Any]:
        pkg = validate_package(package)
        if not execute:
            script_path = Path(hook_script).resolve() if hook_script else self.device.resolve_hook_script(pkg)
            return {
                "executed": False,
                "plan": {
                    "package": pkg,
                    "attach": attach,
                    "hook_script": str(script_path),
                    "so_path": str(so_path) if so_path else None,
                    "timeout": timeout,
                    "bypass": bypass or [],
                },
            }
        self.device.ensure_ready()
        self.device.push_so(pkg, so_path=so_path)
        trace_result = self.device.run_trace(
            package=pkg,
            hook_script=hook_script,
            attach=attach,
            bypass=bypass,
            timeout=timeout,
            so_path=so_path,
        )
        pull_result = self.device.pull_logs(pkg)
        return {
            "executed": True,
            "trace": trace_result,
            "pull": pull_result,
        }

    # ── logs ────────────────────────────────────────────────────

    def list_logs(self, package: str) -> dict[str, Any]:
        pkg = validate_package(package)
        logs_dir = package_logs_dir(self.tool_root, pkg)
        runs: list[dict[str, Any]] = []
        if logs_dir.exists():
            for child in sorted(logs_dir.iterdir(), key=lambda x: x.name):
                if not child.is_dir():
                    continue
                files = [
                    {"name": f.name, "size": f.stat().st_size, "path": str(f)}
                    for f in sorted(child.rglob("*")) if f.is_file()
                ]
                runs.append({
                    "run_id": child.name,
                    "path": str(child),
                    "files": files,
                    "total_size": sum(f["size"] for f in files),
                })
        return {"package": pkg, "logs_dir": str(logs_dir), "exists": logs_dir.exists(), "runs": runs}

    def preview_log(
        self,
        *,
        package: str,
        run_id: str | None = None,
        relative_path: str | None = None,
        max_bytes: int = 8192,
    ) -> dict[str, Any]:
        pkg = validate_package(package)
        logs_dir = package_logs_dir(self.tool_root, pkg)
        if not logs_dir.exists():
            raise XfqtraceError(f"logs 目录不存在: {logs_dir}")

        runs = sorted(
            [d for d in logs_dir.iterdir() if d.is_dir()],
            key=lambda x: x.stat().st_mtime, reverse=True,
        )
        if not runs:
            raise XfqtraceError(f"logs 目录为空: {logs_dir}")

        selected = None
        if run_id:
            for r in runs:
                if r.name == run_id:
                    selected = r
                    break
            if not selected:
                raise XfqtraceError(f"run_id 不存在: {run_id}")
        else:
            selected = runs[0]

        if relative_path:
            target = (selected / relative_path).resolve()
            if not str(target).startswith(str(selected.resolve())):
                raise XfqtraceError("路径越界")
        else:
            candidates = sorted(
                [f for f in selected.rglob("*") if f.is_file()],
                key=lambda x: x.stat().st_size, reverse=True,
            )
            if not candidates:
                raise XfqtraceError("当前 run 目录下无文件")
            target = candidates[0]

        data = target.read_bytes()
        chunk = data[:max_bytes]
        return {
            "package": pkg,
            "run_id": selected.name,
            "file": str(target),
            "bytes_read": len(chunk),
            "total_bytes": len(data),
            "truncated": len(data) > len(chunk),
            "text": chunk.decode("utf-8", errors="replace"),
        }

    # ── logcat ──────────────────────────────────────────────────

    def logcat_command(
        self,
        *,
        serial: str | None = None,
        clear: bool = False,
        tag: str = "xfQTrace:D",
    ) -> dict[str, Any]:
        cmd = ["adb"]
        if serial:
            cmd += ["-s", serial]
        cmd += ["logcat", "-s", tag, "*:S"]
        clear_cmd = None
        if clear:
            clear_cmd = ["adb"]
            if serial:
                clear_cmd += ["-s", serial]
            clear_cmd += ["logcat", "-c"]
        return {
            "command": cmd,
            "command_text": " ".join(cmd),
            "clear_command": clear_cmd,
            "clear_command_text": " ".join(clear_cmd) if clear_cmd else "",
        }


# ── helpers ────────────────────────────────────────────────────

def _file_info(path: Path) -> dict[str, Any]:
    exists = path.exists()
    info: dict[str, Any] = {"path": str(path), "exists": exists}
    if exists:
        s = path.stat()
        info["size"] = s.st_size
        info["is_file"] = path.is_file()
        info["is_dir"] = path.is_dir()
    return info
