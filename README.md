# xfQTrace — 真机 Android NDK 指令级 trace

基于 [xfQTrace](https://github.com/xfq/frida-qbdi-trace)（QBDI + Frida）的真机 trace 工具封装，提供统一的 **CLI** + **MCP Server**。

## 快速开始

```bash
pip install git+https://github.com/Orangechenx/xfqtrace-tools.git

# 检查环境
xfqtrace doctor

# 查看资产
xfqtrace info

# 获取引擎 SO（需提前下载 libxfqtrace.so）
xfqtrace add /path/to/libxfqtrace.so

# 生成 hook 配置
xfqtrace gen-config -p com.example.app --so libnative.so --offset 0x1234

# dry-run 查看计划
xfqtrace run -p com.example.app

# 执行 trace
xfqtrace run -p com.example.app --execute

# 启动 MCP Server
xfqtrace mcp
```

> **注意：** `libxfqtrace.so` 是 xfQTrace 的 native 引擎，不随 pip 包分发。你需要自行获取后运行 `xfqtrace add /path/to/libxfqtrace.so` 完成安装。

## 架构

```
┌─────────────────────────────────────────────┐
│  xfqtrace CLI                                │
│  xfqtrace doctor | info | gen-config | run   │
│  xfqtrace pull-only | list-logs | preview    │
│  xfqtrace logcat | mcp                       │
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

- **Content-Length** — 兼容 Claude Desktop、Cursor 等标准 MCP 客户端
- **JSON Lines** — Python MCP SDK 原生格式

配置 Claude Desktop：

```json
{
  "mcpServers": {
    "xfqtrace": {
      "command": "xfqtrace",
      "args": ["mcp"]
    }
  }
}
```

## 致谢

- [LunFengChen (xfq)](https://github.com/LunFengChen) — [xfQTrace](https://github.com/xfq/frida-qbdi-trace) 基于 QBDI 的 Android native trace 引擎
- [Frida](https://frida.re) — 动态插桩框架
