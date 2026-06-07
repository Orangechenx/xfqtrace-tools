# xfQTrace 使用文档

基于 [LunFengChen (xfq)](https://github.com/LunFengChen) 的 [xfQTrace](https://github.com/xfq/frida-qbdi-trace) 真机 Android NDK 指令级 trace 工具封装，提供 CLI + MCP Server。

## 目录

1. [安装](#1-安装)
2. [快速开始](#2-快速开始)
3. [CLI 命令详解](#3-cli-命令详解)
   - [doctor](#31-doctor-环境检查)
   - [info](#32-info-查看资产)
   - [gen-config](#33-gen-config-生成-hook-配置)
   - [run](#34-run-执行-trace)
   - [pull-only](#35-pull-only-拉取日志)
   - [list-logs / preview-log](#36-list-logs--preview-log-日志管理)
   - [logcat](#37-logcat-监控命令)
   - [mcp](#38-mcp-server)
4. [配置详解](#4-配置详解)
5. [实战场景](#5-实战场景)
6. [MCP Server 配置](#6-mcp-server-配置)
7. [常见问题](#7-常见问题)

---

## 1. 安装

### 从 GitHub 安装（推荐）

```bash
pip install git+https://github.com/Orangechenx/xfqtrace-tools.git
```

安装后 `xfq` 和 `xfqtrace` 两个命令自动可用。

> **注意：** `libxfqtrace.so` 是 xfQTrace 的 native 引擎，不随 pip 包分发。需自行下载后通过 `xfq add /path/to/libxfqtrace.so` 安装。

### 确认安装

```bash
xfq doctor
```

### 查看内置案例

```bash
xfq info
```

### 前置依赖

| 工具 | 用途 | 安装方式 |
|---|---|---|
| `adb` | 设备通信 | `brew install --cask android-platform-tools` / Platform Tools |
| `frida` | 动态插桩 | `pipx install frida-tools` |
| `frida-server` | 设备端 agent | 下载推送到 `/data/local/tmp/` |
| `lz4` | 日志解压 | `brew install lz4`（可选） |

---

## 2. 快速开始

### 最简链路（30 秒跑通）

```bash
# 1. 环境检查
xfq doctor

# 2. 查看内置案例
xfq info

# 3. 安装引擎 SO（需提前下载 libxfqtrace.so）
xfq add /path/to/libxfqtrace.so

# 4. 生成 hook 配置
xfq gen-config -p cn.damai --so libsgmainso-6.7.250504.so --offset 0x57bb8 --overwrite

# 5. 执行 trace
xfq run -p cn.damai --timeout 30 --execute
```

---

## 3. CLI 命令详解

### 3.1 doctor — 环境检查

检查设备连接、frida CLI、frida-server、资产完整性。

```bash
xfq doctor
xfq doctor --serial 11041FDD4003U6     # 指定设备
```

---

### 3.2 info — 查看资产

查看内置工具目录、引擎 SO、案例包列表。

```bash
xfq info
```

---

### 3.3 gen-config — 生成 hook 配置

生成 Frida 注入脚本，写入 `<package>/半自动化trace.js`。

**必填参数：**

```bash
xfq gen-config \
  -p com.example.app \       # 目标包名
  --so libnative.so \        # 目标 SO 名
  --offset 0x1234            # 函数 RVA（支持 0x 十六进制）
```

**可选参数（hook 行为）：**

```bash
xfq gen-config \
  -p cn.damai \
  --so libsgmainso-6.7.250504.so \
  --offset 0x5b198 \
  --hook-args "env,obj,int,jobj" \     # 参数格式化 tag
  --hook-ret jobj \                      # 返回值格式化 tag
  --max-traces 3 \                       # trace 命中次数上限
  --out-format traceui \                 # 输出格式（traceui / xfqtrace）
  --overwrite                            # 覆盖已有文件
```

**可选参数（引擎行为）：**

```bash
  --inline-hook-backend 2 \    # inline hook 后端：0=ShadowHook, 1=frida-gum, 2=Dobby
  --no-lz4 \                   # 关闭 LZ4 压缩
  --sync-flush \               # 同步刷盘（排查崩溃用）
  --anon-trace \               # 启用匿名段 trace
  --memory-trace               # 显式开启内存 trace
```

**可选参数（条件过滤）：**

```bash
  --arg-filter-idx 2 \          # 参数过滤索引
  --arg-filter-value 10401      # 参数过滤目标值（配合 idx，只有 cmd=10401 时才 trace）
```

---

### 3.4 run — 执行 trace

全自动完成：推送 SO → frida 注入 → 等待 trace 完成 → 拉取日志 → 解压。

**默认 dry-run（只输出计划，不实际执行）：**

```bash
xfq run -p cn.damai
```

**真实执行：**

```bash
xfq run -p cn.damai --execute
```

**常用选项：**

```bash
# attach 模式（APP 已在运行）
xfq run -p com.douban.frodo --attach --execute

# 指定超时（默认 120s）
xfq run -p cn.damai --timeout 30 --execute

# 带 bypass 反检测
xfq run -p com.starbucks.cn --bypass bangbang --execute

# 多个 bypass（逗号分隔）
xfq run -p com.example.app --bypass anti_debug,msa --execute

# 自定义 hook 脚本
xfq run -p cn.damai --script /path/to/custom_hook.js --execute

# 指定设备
xfq run -p cn.damai --serial 11041FDD4003U6 --execute
```

**执行过程输出解读：**

```
[*] 推送 libxfqtrace.so (9,520,992 bytes)…     ← push 引擎 SO
[+] SO 已推送: /data/data/.../libxfqtrace.so   ← 确认推送成功
[*] frida: frida -U -f cn.damai ...             ← frida 注入命令
[*] app resumed                                  ← spawn 后恢复进程
[*] detected load: libxxx.so                     ← 目标 SO 加载
[*] engine loaded: 0x...                         ← native 引擎初始化成功
[*] config: {"target":{...}, "options":{...}}    ← 配置下发给引擎
[+] trace armed! libxxx.so+0x1234               ← trace 就绪
[*] trace #1 done                               ← 命中 trace 点，完成
[*] frida 退出 (code=0), traces=1                ← frida 正常退出
[*] 设备上有 N 个 trace 文件                     ← 文件数
[*] 输出目录: .../<package>/logs/<N>/            ← 本地存储路径
  [+] xfqtrace_xxx.log (976,038 bytes)           ← 拉取到本地
```

---

### 3.5 pull-only — 拉取日志

当 run 超时或中断后，单独拉取设备上的 trace 文件：

```bash
xfq pull-only -p cn.damai
xfq pull-only -p cn.damai --execute   # 真实执行拉取
```

---

### 3.6 list-logs / preview-log — 日志管理

**列出日志：**

```bash
xfq list-logs -p cn.damai
```

**预览日志内容：**

```bash
# 预览最新日志（前 8KB）
xfq preview-log -p cn.damai

# 预览指定 run
xfq preview-log -p cn.damai --run-id 1

# 预览前 500 字节
xfq preview-log -p cn.damai --max-bytes 500
```

---

### 3.7 logcat — 监控命令

```bash
# 生成 logcat 命令
xfq logcat

# 带清理缓冲区
xfq logcat --clear

# 指定设备
xfq logcat --serial 11041FDD4003U6
```

---

### 3.8 mcp — MCP Server

```bash
xfq mcp
```

---

## 4. 配置详解

### `hook_format.args` 和 `hook_format.ret` 支持的 tag

| Tag | 说明 | 输出示例 |
|---|---|---|
| `_` / `env` | 跳过 | （无） |
| `jstr` | JNI String → UTF-8 | `"hello world"` |
| `jobj` | Java 对象（自动检测 Object[] 则展开） | `Object[3]{"a", 123, null}` |
| `jbarr` | `byte[]` hex dump | `byte[16]{0A1B2C3D...}` |
| `jmap` | `Map` 遍历 | `Map<3>{k1: v1, k2: v2}` |
| `jmap.diff` | `Map` entry/exit 快照对比 | `+newKey: "value"` |
| `obj` | `jobject` 类名 | `MainActivity@0x7a23...` |
| `int` | 32-bit 有符号整数 | `10401` |
| `long` / `hex` / `ptr` | 64-bit 十六进制 | `0x7bfe8ab130` |
| `bool` | 布尔 | `true` / `false` |
| `cstr` | C 字符串 (`char*`) | `"/proc/self/maps"` |
| `buf.N` | C 缓冲区，长度取第 N 个参数 | `buf[32]{AA BB CC ...}` |

### 完整配置示例

```javascript
const CONFIG = {
    package: "com.example.app",
    target: {
        type: "func",
        so_name: "libtarget.so",
        offset: 0x1234,
    },
    options: {
        inline_hook_backend: 2,      // 0=ShadowHook, 1=frida-gum, 2=Dobby
        out_format: "traceui",       // traceui / xfqtrace / {自定义格式}
        lz4_compression: {
            enable: true,            // LZ4 压缩（默认开启）
            level: 0,                // 0-12（0=最快）
        },
        sync_flush: false,           // 调试模式：每条指令立即刷盘
        stop_condition: {
            max_traces: 1,           // 命中几次后自动停（-1=不限）
        },
        hook_format: {
            args: "env,obj,int,jobj",
            ret: "jobj",
            naming_source: 0,        // trace 文件命名来源
            naming_index: 0,         // 命名取第几个参数的值
        },
        anon_trace: true,            // 匿名段 on-demand 跟踪
        memory_trace: false,         // 内存读写 hexdump
        arg_filter: {
            idx: 2,                  // 按参数索引过滤
            value: 10401,            // 只有 args[idx] == value 时才 trace
        },
    },
};
```

### 输出格式

- **`traceui`**（默认）：紧凑单行格式，适合机器处理和 trace-ui 工具
- **`xfqtrace`**：更偏人工阅读，带寄存器变化、memory hexdump、Hook entry/exit banner

---

## 5. 实战场景

### 5.1 场景一：首次 trace 一个 APP

```bash
# 1. 查看 APP 进程确认包名
adb shell "pm list packages | grep target"

# 2. 查看 native SO
frida -U -n com.target.app -q -e \
  "Process.enumerateModules().filter(m => m.path.includes('.so')).forEach(m => console.log(m.name));"

# 3. 查看 SO 中的导出函数（找 JNI 函数）
frida -U -n com.target.app -q -e "
var mod = Process.findModuleByName('libtarget.so');
Module.enumerateExports('libtarget.so')
  .filter(e => e.name.startsWith('Java_'))
  .forEach(e => console.log('0x' + (e.address - mod.base).toString(16) + ' ' + e.name));
"

# 4. 生成配置
xfq gen-config -p com.target.app --so libtarget.so --offset 0x5678 --overwrite

# 5. 执行 trace
xfq run -p com.target.app --timeout 60 --execute

# 6. 查看结果
xfq preview-log -p com.target.app
```

### 5.2 场景二：大麦 doCommandNative（按 cmd 过滤）

```bash
# 先看 SO 版本
frida -U -n cn.damai -q \
  -e "Process.findModuleByName('libsgmainso-*').then(m => console.log(m.name));"

# 生成带 arg_filter 的配置
xfq gen-config \
  -p cn.damai \
  --so "libsgmainso-6.7.250504.so" \
  --offset 0x5b198 \
  --hook-args "env,obj,int,jobj" \
  --hook-ret jobj \
  --max-traces 3 \
  --arg-filter-idx 2 \
  --arg-filter-value 10401 \
  --overwrite

# 执行
xfq run -p cn.damai --timeout 60 --execute
```

### 5.3 场景三：attach 已运行进程

```bash
# 先打开 APP，确保进程在运行
adb shell "monkey -p com.douban.frodo -c android.intent.category.LAUNCHER 1"

# attach 模式执行
xfq run -p com.douban.frodo --attach --execute
```

### 5.4 场景四：带 bypass 反检测

```bash
# 星巴克（梆梆加固）
xfq run -p com.starbucks.cn --bypass bangbang --execute

# 多 bypass 组合
xfq run -p com.example.app --bypass anti_debug,msa --execute
```

内置 bypass 脚本：

| 名称 | 脚本 | 目标 |
|---|---|---|
| `anti_debug` | `bypass_anti_debug.js` | 通用 anti-debug / anti-frida（ptrace、proc、kill、exit 等） |
| `bangbang` | `bypass_bangbang.js` | 邦梆加固 `libDexHelper.so` 检测 |
| `msa` | `bypass_msa.js` | MSA（小米安全）检测 |

### 5.5 场景五：查看 trace 日志

```bash
# 查看所有 run
xfq list-logs -p cn.damai

# 预览最新日志
xfq preview-log -p cn.damai --max-bytes 2000

# 预览指定 run
xfq preview-log -p cn.damai --run-id 1
```

trace 日志格式示例：

```
[libsgmainso-6.7.250504.so] 0x74f7f07bb8!0x57bb8 sub sp, sp, #0x60; sp=0x74d0973f80  -> sp=0x74d0973f20 
[libsgmainso-6.7.250504.so] 0x74f7f07bbc!0x57bbc stp x29, x30, [sp, #0x30]; x29=0x74d0974000 x30=0x2a sp=0x74d0973f20 
[libsgmainso-6.7.250504.so] 0x74f7f07bc0!0x57bc0 str x27, [sp, #0x40]; x27=0x74f6da6000 sp=0x74d0973f20 
...
```

每行格式：`[模块] 绝对地址!函数偏移 指令; 入寄存器 -> 出寄存器`

---

## 6. MCP Server 配置

MCP Server 支持两种传输格式自动探测，兼容所有标准 MCP 客户端。

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

### Windsurf

MCP 配置文件中添加：

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

### VS Code (GitHub Copilot / Continue)

`.vscode/mcp.json` 或 Continue 插件配置：

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

### MCP 工具列表

| 工具名 | 功能 |
|---|---|
| `xfqtrace_info` | 检查工具资产和案例列表 |
| `xfqtrace_doctor` | 检查设备连接和 frida 状态 |
| `xfqtrace_generate_config` | 生成 hook 脚本 |
| `xfqtrace_run` | 构建 / 执行 trace（`execute=true` 才真实执行） |
| `xfqtrace_list_logs` | 列出本地日志 |
| `xfqtrace_preview_log` | 预览日志内容 |
| `xfqtrace_logcat_command` | 生成 logcat 监控命令 |

---

## 7. 常见问题

### Q: 找不到进程 / attach 失败

`xfq` 会自动通过 `adb shell ps` 解析 PID，然后使用 `frida -p PID` 附加。如果失败，可以手动确认进程存在：

```bash
adb shell "ps | grep com.example.app"
```

### Q: trace 没命中

1. 确认 SO 名和偏移是目标 SO 实际加载的版本（不同 APK 版本 SO 名可能不同）
2. 确认需要触发指定函数才能命中（如 `doCommandNative` 需要 APP 做对应操作）
3. 检查 logcat：`adb logcat -s xfQTrace:D`

### Q: trace 卡住 / 崩溃

```bash
# 重新生成配置，开启 sync_flush 调试
xfq gen-config -p com.example.app --so libtarget.so --offset 0x1234 --sync-flush --overwrite

# 减少 trace 范围
xfq gen-config -p com.example.app --so libtarget.so --offset 0x1234 --max-traces 1 --overwrite

# 换 inline hook 后端
xfq gen-config -p com.example.app --so libtarget.so --offset 0x1234 --inline-hook-backend 1 --overwrite
```

### Q: frida 版本不匹配

`xfq` 不依赖 Python frida 包，全程调系统 `frida` 二进制。只要 `frida --version` 和设备的 `frida-server --version` 一致即可。

### Q: 如何找到函数偏移

```bash
# 方法 1：找导出函数
frida -U -n com.example.app -q -e "
var mod = Process.findModuleByName('libtarget.so');
Module.enumerateExports('libtarget.so')
  .filter(e => e.name.startsWith('Java_'))
  .forEach(e => console.log('0x' + (e.address - mod.base).toString(16) + ' ' + e.name));
"

# 方法 2：用偏移计算工具 get_native_offest.js
# 在设备上装好目标 APP 后运行
```

### Q: SO 版本不对应

安装的 APK 和案例配置中的 SO 版本可能不同。在设备上查实际 SO 名：

```bash
frida -U -n com.example.app -q -e "
Process.enumerateModules().filter(m => m.name.includes('target')).forEach(m => console.log(m.name));
"
```
