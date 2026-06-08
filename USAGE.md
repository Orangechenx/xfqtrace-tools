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
4. [Trace 分析命令](#4-trace-分析命令)
   - [summarize](#41-summarize--算法模式识别)
   - [stack](#42-stack--调用栈可视化)
   - [grep](#43-grep--结构化查询)
   - [search-seq](#44-search-seq--指令序列搜索)
   - [slice](#45-slice--切片导出)
   - [stats](#46-stats--调用指令统计)
   - [regdiff](#47-regdiff--寄存器变化热力图)
   - [mempat](#48-mempat--内存访问模式)
   - [branch](#49-branch--分支命中率分析)
   - [taint](#410-taint--污点分析)
   - [index / query](#411-index--query--sqlite-索引查询)
5. [配置详解](#5-配置详解)
6. [实战场景](#6-实战场景)
7. [MCP Server 配置](#7-mcp-server-配置)
8. [常见问题](#8-常见问题)

---

## 1. 安装

### 从 GitHub 安装（推荐）

```bash
pip install git+https://github.com/Orangechenx/xfqtrace-tools.git

# 或直接从 Release 安装
# pip install https://github.com/Orangechenx/xfqtrace-tools/releases/download/v1.3.2/xfqtrace_tools-1.3.2-py3-none-any.whl
```

安装后 `xfq` 和 `xfqtrace` 两个命令自动可用。

> **注意：** `libxfqtrace.so` 是 xfQTrace 的 native 引擎，不随 pip 包分发。需自行下载后通过 `xfq add /path/to/libxfqtrace.so` 安装。

### 更新已安装版本

如果你通过 GitHub 源码地址安装，更新时直接重新安装：

```bash
python -m pip install -U --force-reinstall git+https://github.com/Orangechenx/xfqtrace-tools.git
```

这条命令由 pip 在临时目录拉取源码并覆盖当前 Python 包，不会和你本地已有项目目录产生 Git 冲突。

如果你通过 Release wheel 安装，换成新版本 wheel 地址：

```bash
python -m pip install -U https://github.com/Orangechenx/xfqtrace-tools/releases/download/v1.3.2/xfqtrace_tools-1.3.2-py3-none-any.whl
```

如果你是本地源码开发安装：

```bash
cd /path/to/xfqtrace-tools
python -m pip install -U -e .
```

只有进入已有源码目录执行 `git pull` 时，才可能和本地未提交修改冲突。开发者应先检查状态：

```bash
git status
git add .
git commit -m "更新 xfqtrace 工具"
git pull --rebase
```

或者临时保存本地修改：

```bash
git stash push -m "本地 xfqtrace 修改"
git pull --rebase
git stash pop
```

`libxfqtrace.so` 不随 pip 包更新。如果 native 引擎也有新版本，需要重新安装引擎：

```bash
xfq add /path/to/new/libxfqtrace.so
```

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
## 4. Trace 分析命令

安装引擎 SO 并成功 trace 后，使用以下命令对日志进行分析。分析命令可以直接读取 `.log` 和 `.log.lz4`，LZ4 文件会流式解压，无需手动预解压。

### 4.1 summarize — 算法模式识别

自动识别 XOR 解密循环、连续内存拷贝等常见算法模式。

```bash
# 分析最新日志
xfq summarize

# 指定日志文件
xfq summarize path/to/trace.log
```

输出示例：

```
指令总数: 9,703
指令行数: 9,703
识别模式: 402
  ├─ xor_loop  L72-L75
  ├─ xor_loop  L92-L95
  ├─ xor_loop  L112-L115
  ...
  ├─ sequential_write  L2-L4     stride=16 count=3

指令分布:
  add:  2,183
  ldrb: 1,231
  strb:   815
  eor:    810
  udiv:   782
```

> 加 `--json` 可输出机器可读的 JSON 格式。

### 4.2 stack — 调用栈可视化

重建函数调用树，一眼看清执行脉络。

```bash
xfq stack                    # 最新 trace
xfq stack trace.log          # 指定文件
xfq stack trace.log --no-collapse   # 不折叠重复调用
```

输出：

```
├─ sub_0x55080
├─ sub_0x5511c
├─ sub_0x1980a0
  ├─ dlopen
  ├─ sub_0x55080
  ├─ sub_0x5511c
    ... x99
```

### 4.3 grep — 结构化查询

按 PC 范围、指令类型、模块、寄存器值过滤 trace 行。寄存器条件支持等值、大小比较和闭区间范围。

```bash
# 按指令类型过滤
xfq grep trace.log --opcode eor

# PC 范围过滤
xfq grep trace.log --pc-range 0x55000-0x56000

# 模块名过滤
xfq grep trace.log --module libsgmain

# 寄存器值过滤
xfq grep trace.log --reg x0=0x1234

# 寄存器比较
xfq grep trace.log --reg 'x0>=0x100'

# 寄存器范围，包含边界
xfq grep trace.log --reg x0:0x100-0x200

# 组合过滤，最多显示 10 条
xfq grep trace.log --opcode str --module libc --max 10
```

支持的寄存器条件格式：

| 格式 | 说明 |
|---|---|
| `x0=0x1234` | 执行前或执行后等于目标值 |
| `x0!=0` | 不等于目标值 |
| `x0>0x100` / `x0>=0x100` | 大于 / 大于等于 |
| `x0<0x200` / `x0<=0x200` | 小于 / 小于等于 |
| `x0:0x100-0x200` | 闭区间范围 |

### 4.4 search-seq — 指令序列搜索

按结构化指令模式匹配一组指令，适合在大 trace 中定位“调用前后”或“参数装载 + 调用”的模式。模式用分号分隔，单条指令支持 `*` 和 `?` wildcard。

```bash
# 相邻匹配：ldr 后紧跟 bl strcmp
xfq search-seq trace.log --seq "ldr x0, *; bl strcmp"

# 非相邻匹配：允许中间隔若干条指令
xfq search-seq trace.log --seq "ldr x0, *; bl strcmp" --non-adjacent

# 非相邻匹配时限制最大间隔
xfq search-seq trace.log --seq "ldr x0, *; bl strcmp" --non-adjacent --max-gap 3

# 限定模块和 PC 范围，并输出前后文
xfq search-seq trace.log --seq "mov x0, *; bl *strcmp*" --module libsgmain --pc-range 0x55000-0x56000 --context 2

# JSON 输出，便于脚本或 MCP 消费
xfq search-seq trace.log --seq "nop" --max 5 --json
```

返回结果包含 `start_line`、`end_line`、`sequence`、`context_before`、`context_after` 等字段。`--max` 会限制最终匹配组数，包含 EOF 前尚未补足后文的 pending 匹配。

### 4.5 slice — 切片导出

从大 trace 中裁剪指定范围，生成新文件。

```bash
# 按行号范围
xfq slice trace.log --line-start 100 --line-end 500 --output snippet.log

# 按 PC 地址范围
xfq slice trace.log --pc-range 0x55000-0x56000 --output snippet.log

# 限制最大行数
xfq slice trace.log --line-start 1 --line-end 1000 --max 200 --output snippet.log

# JSON 输出，查看是否因为 --max 截断
xfq slice trace.log --max 200 --output snippet.log --json
```

`--max` 达到上限后会立即停止读取输入，避免对 GB 级 trace 做无意义扫描。JSON 输出中：

| 字段 | 说明 |
|---|---|
| `total_lines` | 实际已读取行数 |
| `total_lines_exact` | `false` 表示没有继续读取剩余行，`total_lines` 不是全文件精确总行数 |
| `truncated` | `true` 表示输出因为 `--max` 被截断 |
| `written_lines` | 实际写入输出文件的行数 |
| `skipped_lines` | 因 PC 范围等过滤条件跳过的行数 |

### 4.6 stats — 调用/指令统计

统计函数调用次数和指令分布。

```bash
xfq stats trace.log

# 附加解析诊断，定位无法解析的日志行
xfq stats trace.log --parse-stats

# JSON 输出
xfq stats trace.log --parse-stats --json
```

输出：

```
指令总数: 9,703
函数调用: 87

调用分布 (Top 10):
  sub_0x55080                          15 ███████████████
  sub_0x5511c                          14 ██████████████

指令分布 (Top 10):
  add                     2183
  ldrb                    1231
```

### 4.7 regdiff — 寄存器变化热力图

统计每个寄存器的变化次数、首次/末次值，快速发现关键寄存器。

```bash
# 全部寄存器
xfq regdiff trace.log

# 关注特定寄存器
xfq regdiff trace.log --regs x0,x1,x8
```

输出：

```
寄存器  变化次数  首次值                  末次值
x8     595      0x74f6278000             0x42fad59f84b95c4d
x0     7        0x74f817a178             0x7645456a10
```

### 4.8 mempat — 内存访问模式

检测连续内存读写模式（memcpy / memset / 顺序读取特征）。

```bash
xfq mempat trace.log
```

输出：

```
sequential_write     L1-L5    stride=8 count=5
sequential_read      L9-L14   stride=4 count=6
```

### 4.9 branch — 分支命中率分析

统计条件跳转指令的跳转/不跳转次数，识别死代码和关键决策点。

```bash
xfq branch trace.log
xfq branch trace.log --min-rate 90   # 只看跳转率 > 90% 的分支
```

输出：

```
模块                 偏移      指令         跳转   不跳   跳转率
libsgmainso          0x55110   b.ne #-0x4c  156    0     100.0%
libsgmainso          0x55084   cbz w1,#0x90 15     0     100.0%
```

说明：

- AArch64 trace 默认按 4 字节指令估算 fallthrough，JSON 中会标注 `arch_assumption: aarch64_fixed_4_bytes`。
- 如果日志模块名包含 Thumb 标记或可从地址推断 Thumb，会标注 `thumb_inferred_2_bytes`。
- `br`、`blr` 等间接跳转会统计为 `type=indirect`，不强行推断命中率。

### 4.10 taint — 污点分析

标记一个或多个输入（寄存器/内存地址），自动跟踪其在 trace 中的传播路径，判断返回值是否受其影响。用于快速确定参数是否参与了签名、加密或校验计算。

```bash
# 标记寄存器 x2（第三个参数）为污点源
xfq taint trace.log --taint x2

# 标记多个寄存器
xfq taint trace.log --taint x2 --taint x3

# 标记内存范围
xfq taint trace.log --taint-mem 0x7a000000-0x7a000100

# 只看结论不看详细路径
xfq taint trace.log --taint x2 --summary

# 只看前 5 条传播链
xfq taint trace.log --taint x2 --max-prop 5

# JSON 输出
xfq taint trace.log --taint x2 --json
```

注意：

- 内存污点按地址粒度记录，不模拟完整字节级别 CPU 语义；`strb` 等部分写会在输出 warning 中说明。
- `--taint-mem` 使用区间摘要存储，不会为大范围内的每个地址初始化一个字典项。
- `w0` 等 32 位寄存器写入会清理对应 `x0` 的旧污点，避免高位污点误留。

输出：
```
污点分析结果 — 9,703 条指令

  🎯 返回值 x0 被污染! (标签: input:x2)
  传播链: 832 条
  污染寄存器: 20 个
  污染内存: 813 处

传播路径 (前 50 条):

  L    55  →  x10     <- input:x2    add x10, x2, #0x1
  L    58  →  x13     <- input:x2    add x13, x10, x8
  L   324  →  x11     <- input:x2    eor w11, w12, w11
  L   325  →  0x...                  strb w11, [x15, #0x1]
```

**基本原理：** 扫描 trace 中的每条指令，维护寄存器/内存地址到污点标签的映射。`str` 将污点写入内存，`ldr` 从内存读回，`add/eor/mov` 等 ALU 指令将源操作数的污点传递给目标寄存器。不依赖指令模拟，利用 trace 中已有的寄存器值进行传播，准确率在栈内存场景下可达 95% 以上。

### 4.11 index / query — SQLite 索引查询

当同一个大 trace 需要反复查询时，可以先导入 SQLite 索引库。原始 `.log` / `.log.lz4` 仍然保留，`trace.db` 只是可删除重建的查询缓存。

```bash
# 建立索引，默认不覆盖已有 db
xfq index trace.log --db trace.db

# 覆盖重建
xfq index trace.log.lz4 --db trace.db --replace

# JSON 输出导入统计
xfq index trace.log --db trace.db --json
```

索引库核心表：

| 表 | 说明 |
|---|---|
| `trace_file` | 原始 trace 文件路径、大小、hash、导入统计 |
| `insn` | 指令主表，包含行号、模块、地址、opcode、操作数、原始行 |
| `reg_access` | 寄存器 before/after 值和 `changed` 写入标记 |
| `mem_access` | load/store 的读写方向、解析出的内存地址和大小 |
| `parse_error` | 非指令行或解析失败行，便于排查日志格式漂移 |

常用查询：

```bash
# 查谁写入了 x0
xfq query-reg trace.db --write x0

# 查 bl 指令
xfq query-op trace.db --opcode bl

# 限定模块
xfq query-op trace.db --opcode str --module libsgmain

# 查相邻指令序列
xfq query-seq trace.db --seq "ldr x0, *; bl strcmp" --context 2

# 执行只读 SQL
xfq query trace.db --sql "SELECT line_no, module, insn FROM insn WHERE opcode='bl' LIMIT 20"
```

`query` 只允许单条 `SELECT` / `WITH` 查询，并开启 SQLite `query_only`，避免误删索引库。查寄存器时不要用 `LIKE '%x0%'`，应使用 `reg_access`：

```sql
SELECT i.*
FROM reg_access r
JOIN insn i ON i.id = r.insn_id
WHERE r.reg = 'x0'
  AND r.changed = 1;
```

相比直接 `grep/search-seq`，索引查询的优势是“导入一次，多次复用解析结果”。如果只查一次小日志，直接用原有命令更简单；如果是几百 MB 或 GB 级日志反复探索，优先建索引。

---

## 5. 配置详解

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

## 6. 实战场景

### 6.1 场景一：首次 trace 一个 APP

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

### 6.2 场景二：大麦 doCommandNative（按 cmd 过滤）

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

### 6.3 场景三：attach 已运行进程

```bash
# 先打开 APP，确保进程在运行
adb shell "monkey -p com.douban.frodo -c android.intent.category.LAUNCHER 1"

# attach 模式执行
xfq run -p com.douban.frodo --attach --execute
```

### 6.4 场景四：带 bypass 反检测

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

### 6.5 场景五：查看 trace 日志

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

## 7. MCP Server 配置

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
| `xfqtrace_summarize` | 智能摘要和算法模式识别 |
| `xfqtrace_stack` | 重建调用栈 |
| `xfqtrace_grep` | 结构化查询 trace 行 |
| `xfqtrace_search_sequence` | 指令序列搜索 |
| `xfqtrace_stats` | 调用/指令统计 |
| `xfqtrace_regdiff` | 寄存器变化统计 |
| `xfqtrace_mempat` | 内存访问模式检测 |
| `xfqtrace_branch` | 分支命中率分析 |
| `xfqtrace_taint` | 污点传播分析 |

分析类 MCP 工具支持直接传 `text`、传 `input` 文件路径，或传 `package` 自动解析本地日志；当同一包有多个 run 时可用 `run_id` 指定目录。

---

## 8. 常见问题

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
