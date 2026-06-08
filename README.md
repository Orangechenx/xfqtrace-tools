# xfQTrace — 真机 Android NDK 指令级 trace

基于 [LunFengChen (xfq)](https://github.com/LunFengChen) 的 [xfQTrace](https://github.com/xfq/frida-qbdi-trace)（QBDI + Frida）的真机 trace 工具封装，提供统一的 **CLI** + **MCP Server**。

## 快速开始

```bash
# 从 GitHub 安装
pip install git+https://github.com/Orangechenx/xfqtrace-tools.git

# 或直接从 Release 安装
# pip install https://github.com/Orangechenx/xfqtrace-tools/releases/download/v1.3.2/xfqtrace_tools-1.3.2-py3-none-any.whl

# 已安装后更新到 GitHub 最新版本
pip install -U --force-reinstall git+https://github.com/Orangechenx/xfqtrace-tools.git

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

# 为本地 trace 生成 SQLite 索引并快速查询
xfq index trace.log --db trace.db
xfq query-reg trace.db --write x0
```

> **注意：** `libxfqtrace.so` 是 xfQTrace 的 native 引擎，不随 pip 包分发。你需要自行获取后运行 `xfq add /path/to/libxfqtrace.so` 完成安装。

## 更新方式

如果你是通过 pip 安装的，更新时直接重新安装即可，pip 会使用临时目录拉取源码并覆盖当前 Python 包，不会和本地项目目录产生 Git 冲突：

```bash
pip install -U --force-reinstall git+https://github.com/Orangechenx/xfqtrace-tools.git
```

如果你是从 Release wheel 安装的，换成新版本 wheel 地址：

```bash
pip install -U https://github.com/Orangechenx/xfqtrace-tools/releases/download/v1.3.2/xfqtrace_tools-1.3.2-py3-none-any.whl
```

只有在你进入已有源码目录执行 `git pull` 时，才可能因为本地未提交修改产生冲突。开发者应先 `git status`，提交或 stash 本地改动后再拉取。

`libxfqtrace.so` 不随 pip 包更新。如果 native 引擎也有新版本，需要重新运行：

```bash
xfq add /path/to/new/libxfqtrace.so
```

## 架构

```
┌─────────────────────────────────────────────┐
│  xfq CLI                                     │
│  xfq doctor | info | gen-config | run        │
│  xfq pull-only | list-logs | preview         │
│  xfq grep | search-seq | taint | branch      │
│  xfq index | query | query-reg | query-op     │
│  xfq logcat | mcp                            │
├─────────────────────────────────────────────┤
│  xfqtrace.core     核心业务逻辑              │
│  xfqtrace.device   adb + frida 设备管理      │
│  xfqtrace.analyzer 兼容门面，分析器已模块化  │
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
| **设备 & 资产** | |
| `doctor` | 检查 adb/frida/frida-server/资产 |
| `info` | 查看工具资产和案例列表 |
| `add` | 将 libxfqtrace.so 复制到包内 _vendor/ 目录 |
| **Trace 执行** | |
| `gen-config` | 生成 Frida hook 脚本 |
| `run` | 执行 trace（默认 dry-run） |
| `pull-only` | 仅拉取设备 trace 日志 |
| `list-logs` | 列出本地日志 |
| `preview-log` | 预览日志内容 |
| **Trace 分析** | |
| `summarize` | 智能摘要 — 识别 XOR 循环、内存拷贝等算法模式 |
| `stack` | 调用栈可视化 — 重建函数调用树 |
| `grep` | 结构化查询 — 按 PC/指令/寄存器条件过滤，支持比较和范围 |
| `search-seq` | 指令序列搜索 — 匹配相邻/非相邻指令序列 |
| `slice` | 切片导出 — 裁剪 trace 到指定范围 |
| `stats` | API 调用统计 — 函数调用次数、指令分布和可选解析诊断 |
| `regdiff` | 寄存器变化热力图 — 统计寄存器变化情况 |
| `mempat` | 内存访问模式检测 — 识别连续内存拷贝/置零 |
| `branch` | 分支命中率分析 — 条件跳转统计 |
| `taint` | 污点分析 — 标记输入，跟踪数据传播路径 |
| `index` | SQLite 索引 — 将 trace 导入本地结构化索引库 |
| `query` | SQL 查询 — 对索引库执行只读 SELECT |
| `query-reg` | 索引查询 — 快速查寄存器写入/访问 |
| `query-op` | 索引查询 — 快速查 opcode/module |
| `query-seq` | 索引查询 — 快速查相邻指令序列 |
| **MCP** | |
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
| `xfqtrace_summarize` | 智能摘要和算法模式识别 |
| `xfqtrace_stack` | 重建调用栈 |
| `xfqtrace_grep` | 结构化查询 trace 行 |
| `xfqtrace_search_sequence` | 指令序列搜索 |
| `xfqtrace_stats` | 调用/指令统计 |
| `xfqtrace_regdiff` | 寄存器变化统计 |
| `xfqtrace_mempat` | 内存访问模式检测 |
| `xfqtrace_branch` | 分支命中率分析 |
| `xfqtrace_taint` | 污点传播分析 |

## 分析能力补充

- `.log` 和 `.log.lz4` 均可直接分析，LZ4 文件会流式读取，无需手动解压。
- `summarize`、`grep`、`search-seq`、`mempat`、`branch`、`taint` 等核心分析尽量流式扫描，避免大 trace 全量载入内存。
- `slice --max` 会在写满后停止读取；JSON 中 `truncated=true` 且 `total_lines_exact=false` 表示没有继续统计剩余行数。
- `branch` 默认按 AArch64 4 字节指令估算 fallthrough；遇到 Thumb 标记或可推断 Thumb 场景时会标注 `thumb_inferred_2_bytes`。
- `index` 会把 trace 导入 SQLite，生成的 `trace.db` 是可删除重建的查询索引，不替代原始日志。

## 致谢

- [LunFengChen (xfq)](https://github.com/LunFengChen) — [xfQTrace](https://github.com/xfq/frida-qbdi-trace) 基于 QBDI 的 Android native trace 引擎
- [Frida](https://frida.re) — 动态插桩框架
