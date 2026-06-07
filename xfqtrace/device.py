from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from . import config as cfg


class FridaDevice:
    """通过 subprocess 管理 adb + frida CLI，不依赖 frida Python 包。"""

    def __init__(self, serial: str | None = None, tool_root: str | Path | None = None) -> None:
        self.serial = serial
        self.tool_root = cfg.resolve_tool_root(tool_root)
        self._resolved_serial: str | None = None

    # ── adb helpers ──────────────────────────────────────────────

    def _adb(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)
        env = os.environ.copy()
        env["MSYS_NO_PATHCONV"] = "1"
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)

    def _adb_shell(self, command: str, root: bool = True, timeout: int = 15) -> subprocess.CompletedProcess:
        if root:
            command = f'su -c "{command}"'
        return self._adb("shell", command, timeout=timeout)

    def resolve_serial(self) -> str:
        """自动检测设备序列号。"""
        if self._resolved_serial:
            return self._resolved_serial
        if self.serial:
            self._resolved_serial = self.serial
            return self._resolved_serial
        r = self._adb("devices", timeout=10)
        for line in r.stdout.splitlines()[1:]:
            line = line.strip()
            if line and "device" in line and "offline" not in line:
                self._resolved_serial = line.split()[0]
                return self._resolved_serial
        raise RuntimeError("未发现 Android 设备，请连接设备并确认 adb 可用")

    # ── frida-server 管理 ────────────────────────────────────────

    def check_frida_server(self) -> bool:
        """检查设备 frida-server 是否在运行。"""
        serial = self.resolve_serial()
        r = subprocess.run(
            ["adb", "-s", serial, "shell", "ps", "|", "grep", "frida-server"],
            capture_output=True, text=True, timeout=10,
        )
        return "frida-server" in r.stdout

    def start_frida_server(self) -> None:
        """启动设备 frida-server。"""
        serial = self.resolve_serial()
        print("[*] 正在启动 frida-server…")
        self._adb_shell("nohup /data/local/tmp/frida-server > /dev/null 2>&1 &", timeout=10)
        time.sleep(3)
        self._setup_forward()

    def _setup_forward(self) -> None:
        serial = self.resolve_serial()
        # 先清理旧转发
        subprocess.run(["adb", "-s", serial, "forward", "--remove-all"],
                       capture_output=True, timeout=10)
        subprocess.run(["adb", "-s", serial, "forward", "tcp:27042", "tcp:27042"],
                       capture_output=True, timeout=10)

    def ensure_ready(self) -> None:
        """确保设备连接、frida-server 运行、adb forward 就绪。"""
        self.resolve_serial()
        serial = self._resolved_serial
        # adb forward
        r = subprocess.run(["adb", "-s", serial, "forward", "--list"],
                           capture_output=True, text=True, timeout=10)
        if "27042" not in r.stdout:
            self._setup_forward()
        # frida-server
        if not self.check_frida_server():
            self.start_frida_server()
        # 等待 frida 就绪
        for _ in range(10):
            r = subprocess.run(
                ["adb", "-s", serial, "shell", "ps", "|", "grep", "frida-server"],
                capture_output=True, text=True, timeout=10,
            )
            if "frida-server" in r.stdout:
                return
            time.sleep(1)
        raise RuntimeError("frida-server 启动失败")

    # ── 资产推送 ─────────────────────────────────────────────────

    def push_so(self, package: str, so_path: str | Path | None = None) -> None:
        """推送 libxfqtrace.so 到目标 app 私有目录。"""
        serial = self.resolve_serial()
        so_local = cfg.engine_so_path(self.tool_root, explicit=so_path)
        if not so_local.exists():
            raise FileNotFoundError(
                f"引擎 SO 不存在: {so_local}\n"
                f"请将 libxfqtrace.so 放入 {cfg.tool_asset(self.tool_root, BIN_DIR)}/ 目录，\n"
                f"或用 --so-path 指定路径"
            )

        remote_dir = f"/data/data/{package}/files"
        remote = f"{remote_dir}/libxfqtrace.so"
        tmp = "/data/local/tmp/libxfqtrace.so"

        print(f"[*] 推送 {so_local.name} ({so_local.stat().st_size:,} bytes)…")
        self._adb("push", str(so_local), tmp)
        self._adb_shell(f"mkdir -p {remote_dir}")
        self._adb_shell(f"cp {tmp} {remote}")

        # 修复所有者
        owner_r = self._adb_shell(f"stat -c %u:%g /data/data/{package}")
        owner = owner_r.stdout.strip()
        if owner:
            self._adb_shell(f"chown -R {owner} {remote_dir}")
        self._adb_shell(f"chmod 755 {remote}")
        self._adb_shell(f"chcon u:object_r:app_data_file:s0 {remote}")
        print(f"[+] SO 已推送: {remote}")

    # ── hook 脚本解析 ────────────────────────────────────────────

    def resolve_hook_script(self, package: str) -> Path:
        """优先包级脚本，回退到默认模板。"""
        pkg_script = cfg.package_hook_script(self.tool_root, package)
        if pkg_script.exists():
            return pkg_script
        default = cfg.default_hook_script(self.tool_root)
        if default.exists():
            return default
        raise FileNotFoundError(f"未找到 hook 脚本: {pkg_script} 或 {default}")

    def resolve_bypass_scripts(self, names: list[str]) -> list[Path]:
        paths: list[Path] = []
        for name in names:
            p = cfg.bypass_script(self.tool_root, name)
            if not p.exists():
                raise FileNotFoundError(f"bypass 脚本不存在: {p}")
            paths.append(p)
        return paths

    @staticmethod
    def _infer_max_traces(script_text: str) -> int | None:
        m = re.search(r"stop_condition\s*:\s*\{\s*max_traces\s*:\s*(-?\d+)", script_text)
        if m:
            try:
                v = int(m.group(1))
                return v if v > 0 else None
            except ValueError:
                pass
        return None

    # ── 执行 trace ───────────────────────────────────────────────

    def run_trace(
        self,
        package: str,
        hook_script: str | Path | None = None,
        attach: bool = False,
        bypass: list[str] | None = None,
        timeout: int = 120,
        so_path: str | Path | None = None,
    ) -> dict:
        """通过 subprocess 调 frida CLI 执行 trace。"""
        serial = self.resolve_serial()
        script_path = Path(hook_script).resolve() if hook_script else self.resolve_hook_script(package)
        if not script_path.exists():
            raise FileNotFoundError(f"hook 脚本不存在: {script_path}")

        script_text = script_path.read_text(encoding="utf-8")
        expected_traces = self._infer_max_traces(script_text)

        # 合并 bypass 脚本到临时 agent（frida CLI 只接受一个 -l）
        merged_script = self._merge_bypass(script_path, bypass or [])

        # attach 模式：先解析 PID，用 -p 而非 -n
        target_pid = None
        if attach:
            target_pid = self._resolve_pid(package)
            if not target_pid:
                # 回退：用 -n 让 frida 自己找
                pass

        # 构造 frida 命令
        frida_cmd = self._build_frida_command(
            package, merged_script, attach, timeout, target_pid
        )
        print(f"[*] frida: {' '.join(frida_cmd)}")

        # 启动 frida 进程
        proc = subprocess.Popen(
            frida_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdin is not None

        # spawn 模式需要手动 resume
        if not attach:
            time.sleep(2)
            proc.stdin.write("%resume\n")
            proc.stdin.flush()
            print("[*] app resumed")

        # 监控输出
        trace_count = 0
        done = False
        frida_stdout: list[str] = []
        start_ts = time.monotonic()

        def reader_thread(stream, store):
            for line in iter(stream.readline, ""):
                store.append(line)

        import threading
        t = threading.Thread(target=reader_thread, args=(proc.stdout, frida_stdout), daemon=True)
        t.start()

        # 等待 trace_done 或超时
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in frida_stdout[-50:]:
                if "trace_done" in line:
                    trace_count += 1
                    print(f"[*] trace #{trace_count} done")
                    if expected_traces and trace_count >= expected_traces:
                        done = True
                        break
            if done:
                break
            time.sleep(0.5)

        # 清理
        proc.stdin.close()
        proc.wait(timeout=5)
        stdout_all = "".join(frida_stdout)

        # 清理临时 agent 文件
        if merged_script != script_path and merged_script.exists():
            try:
                merged_script.unlink()
            except OSError:
                pass

        print(f"[*] frida 退出 (code={proc.returncode}), traces={trace_count}")
        return {
            "package": package,
            "trace_count": trace_count,
            "expected": expected_traces,
            "done": done,
            "frida_exit_code": proc.returncode,
            "frida_stdout": stdout_all,
            "duration_sec": int(time.monotonic() - start_ts),
        }

    def _merge_bypass(self, hook_script: Path, bypass: list[str]) -> Path:
        """将 bypass 脚本与主 hook 脚本合并为一个临时 agent 文件。

        frida CLI 只接受一个 -l，所以需要把多个脚本拼在一起。
        先注入 bypass（反检测），再注入主 trace 脚本。
        """
        if not bypass:
            return hook_script  # 无需合并

        bypass_paths = self.resolve_bypass_scripts(bypass)
        lines: list[str] = [
            "// ===== xfQTrace merged agent: bypass + trace =====\n",
        ]
        for bp in bypass_paths:
            lines.append(f"\n// ===== bypass: {bp.name} =====\n")
            lines.append(bp.read_text(encoding="utf-8"))

        lines.append(f"\n// ===== trace 主脚本: {hook_script.name} =====\n")
        lines.append(hook_script.read_text(encoding="utf-8"))

        import tempfile
        fd, tmp_path = tempfile.mkstemp(suffix=".js", prefix="xfqtrace-agent-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = Path(tmp_path)
        print(f"[*] 合并 agent ({len(bypass)} bypass + trace) -> {result.name}")
        return result

    def _resolve_pid(self, package: str) -> int | None:
        """通过 adb shell ps 解析目标进程 PID（先 root、回退无 root）。"""
        serial = self.resolve_serial()
        for use_root in [True, False]:
            r = self._adb_shell(f"ps | grep ' {package}$'", root=use_root, timeout=10)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        continue
        return None

    def _build_frida_command(
        self, package: str, script_path: Path, attach: bool, timeout: int,
        target_pid: int | None = None,
    ) -> list[str]:
        cmd: list[str] = []
        frida_bin = os.environ.get("XFQTRACE_FRIDA", "frida")
        cmd.append(frida_bin)
        if self.serial:
            cmd += ["-D", self.serial]
        else:
            cmd += ["-U"]

        if attach:
            if target_pid:
                cmd += ["-p", str(target_pid)]
            else:
                cmd += ["-n", package]
        else:
            cmd += ["-f", package]

        cmd += ["-l", str(script_path), "-q", "-t", str(timeout)]
        return cmd

    # ── 拉取日志 ─────────────────────────────────────────────────

    def pull_logs(self, package: str, session_dir: str | Path | None = None) -> dict:
        """从设备拉取 trace 日志到本地 logs/<N>/ 目录。"""
        serial = self.resolve_serial()
        trace_dir = f"/data/data/{package}/files/trace_logs"

        # 列出远程文件
        r = self._adb_shell(f"ls {trace_dir}/")
        stdout = r.stdout.strip()
        if not stdout:
            return {"pulled": False, "reason": "设备上无 trace 文件", "files": []}

        remote_files = [f.strip() for f in stdout.splitlines() if f.strip()]
        print(f"[*] 设备上有 {len(remote_files)} 个 trace 文件")

        # 确定本地输出目录
        logs_root = cfg.package_logs_dir(self.tool_root, package)
        logs_root.mkdir(parents=True, exist_ok=True)
        existing = [int(d.name) for d in logs_root.iterdir() if d.is_dir() and d.name.isdigit()]
        seq = max(existing) + 1 if existing else 1
        out_dir = Path(session_dir) if session_dir else logs_root / str(seq)
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] 输出目录: {out_dir}")

        # chmod 方便读取
        self._adb_shell(f"chmod -R 777 {trace_dir}")

        pulled: list[dict] = []
        for fname in remote_files:
            remote = f"{trace_dir}/{fname}"
            local_path = out_dir / fname
            tmp = f"/data/local/tmp/{fname}"

            self._adb_shell(f"cp {remote} {tmp} && chmod 644 {tmp}")
            pull_r = self._adb("pull", tmp, str(local_path))
            if pull_r.returncode != 0:
                print(f"  [!] pull 失败: {fname}")
                continue
            self._adb_shell(f"rm -f {tmp}")

            sz = local_path.stat().st_size
            print(f"  [+] {fname} ({sz:,} bytes)")

            # LZ4 解压
            decompressed = None
            if fname.endswith(".lz4"):
                decompressed = self._decompress_lz4(local_path, out_dir)

            pulled.append({
                "name": fname,
                "path": str(local_path),
                "size": sz,
                "decompressed": str(decompressed) if decompressed else None,
            })

        return {"pulled": True, "session_dir": str(out_dir), "files": pulled}

    def _decompress_lz4(self, lz4_path: Path, out_dir: Path) -> Path | None:
        """解压 .lz4 文件，返回解压后路径或 None。"""
        out_path = out_dir / lz4_path.name[:-4]
        # 优先用系统 lz4
        lz4_bin = self._find_lz4()
        if not lz4_bin:
            print(f"  [~] lz4 不可用，跳过解压: {lz4_path.name}")
            return None
        r = subprocess.run(
            [lz4_bin, "-d", "-f", str(lz4_path), str(out_path)],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0 and (not out_path.exists() or out_path.stat().st_size == 0):
            print(f"  [!] 解压失败: {r.stderr.strip()}")
            return None
        raw_sz = out_path.stat().st_size
        compressed_sz = lz4_path.stat().st_size
        ratio = (1 - compressed_sz / raw_sz) * 100 if raw_sz else 0
        status = "部分解压" if r.returncode != 0 else "解压完成"
        print(f"  [+] -> {out_path.name} ({raw_sz:,} bytes, {ratio:.0f}% 压缩率) [{status}]")
        if r.returncode == 0:
            lz4_path.unlink(missing_ok=True)
        return out_path

    @staticmethod
    def _find_lz4() -> str | None:
        """查找 lz4 可执行文件。"""
        import platform as _platform
        is_win = _platform.system() == "Windows"
        cmd = "where" if is_win else "which"
        name = "lz4.exe" if is_win else "lz4"
        r = subprocess.run([cmd, name], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
        return None

    # ── 诊断 ─────────────────────────────────────────────────────

    def doctor(self) -> dict:
        """检查环境完整性。"""
        serial = self.resolve_serial()
        adb_ok = True
        try:
            r = self._adb("devices", timeout=5)
            adb_ok = "device" in r.stdout
        except Exception:
            adb_ok = False

        frida_ok = False
        frida_ver = ""
        try:
            r = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                frida_ok = True
                frida_ver = r.stdout.strip()
        except Exception:
            pass

        frida_server_ok = self.check_frida_server() if adb_ok else False

        so_ok = cfg.engine_so_path(self.tool_root).exists()

        lz4_ok = self._find_lz4() is not None

        return {
            "device": {"serial": serial, "connected": adb_ok},
            "frida": {"cli_ok": frida_ok, "cli_version": frida_ver, "server_running": frida_server_ok},
            "assets": {
                "tool_root": str(self.tool_root),
                "tool_root_exists": self.tool_root.exists(),
                "engine_so": so_ok,
            },
            "tools": {"lz4": lz4_ok},
        }
