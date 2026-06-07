# xfQTrace — 真机 Android NDK 指令级 trace

基于 [LunFengChen (xfq)](https://github.com/LunFengChen) 的 [xfQTrace](https://github.com/xfq/frida-qbdi-trace)（QBDI + Frida）的真机 trace 工具封装，提供统一的 **CLI** + **MCP Server**。

## 快速开始

```bash
pip install git+https://github.com/Orangechenx/xfqtrace-tools.git

# 检查环境
xfq doctor

# 查看资产
xfq info

# 获取引擎 SO（需提前下载 libxfqtrace.so）
xfq add /path/to/libxfqtrace.so

# 生成 hook 配置
xfq gen-config -p com.example.app --so libnative.so --offset 0x1234

# dry-run 查看计划
xfq run -p com.example.app

# 执行 trace
xfq run -p com.example.app --execute

# 启动 MCP Server
xfq mcp
```

> **注意：** `libxfqtrace.so` 是 xfQTrace 的 native 引擎，不随 pip 包分发。你需要自行获取后运行 `xfq add /path/to/libxfqtrace.so` 完成安装。

## 架构

```
┌─────────────────────────────────────────────┐
│  xfq CLI                                     │
│  xfq doctor | info | gen-config | run        │
│  xfq pull-only | list-logs | preview         │
│  xfq logcat | mcp                            │
├─────────────────────────────────────────────┤
│  xfqtrace.core     核心业务逻辑              │
│  xfqtrace.device   adb + frida 设备管理      │
│  xfqtrace.mcp_server  MCP Server (双格式)     │
├─────────────────────────────────────────────┤
│  xfqtrace/_vendor/  内置资产                 │
│    ├── libxfqtrace.so  ← 需 add 安装 (引擎)  │
│    ├── 半自动化trace.js   (Frida 模板)       │
│    ├── scripts/           (bypass 脚本)      │
│    └── <package>/         (案例配置)          │
└─────────────────────────────────────────────┘
```

**设计原则：** 不依赖 `import frida`，全程 subprocess 调系统 `frida` CLI，无版本匹配问题。

## 命令

| 命令 | 说明 |
|---|---|
| `doctor` | 检查 adb/frida/frida-server/资产 |
| `info` | 查看工具资产和案例列表 |
| `add` | 将 libxfqtrace.so 复制到包内 _vendor/ 目录 |
| `gen-config` | 生成 Frida hook 脚本 |
| `run` | 执行 trace（默认 dry-run） |
| `pull-only` | 仅拉取设备 trace 日志 |
| `list-logs` | 列出本地日志 |
| `preview-log` | 预览日志内容 |
| `logcat` | 输出 logcat 监控命令 |
| `mcp` | 启动 MCP Server |

## MCP Server

支持两种传输格式自动探测：

- **Content-Length** — 兼容所有标准 MCP 客户端
- **JSON Lines** — Python MCP SDK 原生格式

配置方式针对不同客户端：

### Claude Desktop

```json
{
  "mcpServers": {
    "xfqtrace": {
      "command": "xfq",
      "args": ["mcp"]
    }
  }
}
```

### Cursor

Settings → Features → MCP Servers → Add New：

```
Name: xfqtrace
Type: command
Command: xfq
Args: mcp
```

### Windsurf / Codex CLI / Claude Code 等 CLI 工具

所有基于 stdio 的 MCP CLI 工具配置方式相同，只是配置文件路径不同：

```json
{
  "mcpServers": {
    "xfqtrace": {
      "command": "xfq",
      "args": ["mcp"]
    }
  }
}
```

配置文件位置：

| 工具 | 路径 |
|---|---|
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Codex CLI | `~/.codexclirc` 或环境变量 `CODEX_MCP_SERVERS` |
| Claude Code | 环境变量 `CLAUDE_CODE_MCP_SERVERS` |
| Cline | `~/.cline/mcp_settings.json` |
| 通用 MCP 客户端 | 任意支持 stdio 传输的 MCP 配置 |

### VS Code (GitHub Copilot / Continue)

`.vscode/mcp.json` 或 Continue 配置：

```json
{
  "mcpServers": {
    "xfqtrace": {
      "command": "xfq",
      "args": ["mcp"]
    }
  }
}
```

### 手动测试

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | xfq mcp
```

### 可用工具

| 工具名 | 功能 |
|---|---|
| `xfqtrace_info` | 检查工具资产和案例列表 |
| `xfqtrace_doctor` | 检查设备连接和 frida 状态 |
| `xfqtrace_generate_config` | 生成 Frida hook 脚本 |
| `xfqtrace_run` | 构建或执行 trace |
| `xfqtrace_list_logs` | 列出本地日志 |
| `xfqtrace_preview_log` | 预览日志内容 |
| `xfqtrace_logcat_command` | 生成 logcat 监控命令 |

## 致谢

- [LunFengChen (xfq)](https://github.com/LunFengChen) — [xfQTrace](https://github.com/xfq/frida-qbdi-trace) 基于 QBDI 的 Android native trace 引擎
- [Frida](https://frida.re) — 动态插桩框架
