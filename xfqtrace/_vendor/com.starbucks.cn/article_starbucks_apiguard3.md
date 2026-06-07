# 实战记录：星巴克 App 反 trace 拆解 —— ApiGuard3 如何识破 QBDI 代码缓存

> 写在前面：本文是一次完整的攻防记录。从 push SO、注入 bypass、启动 trace，到看着 app 崩溃自动重启，再一步步定位"凶手"是谁、它怎么发现我们的。文章中的工具 **xfQTrace** 是我自己写的基于 QBDI 的 Android trace 框架（暂未开源），文中只描述外部行为，不展开内部实现。

---

## 0. TL;DR

- **目标**：trace `com.starbucks.cn` 内部加密 SO `libcfbe0b.so` 的 `+0xFED4` 函数
- **现象**：跑了大约 1450 条指令后 app 崩溃，被 zygote 自动拉起又崩，无限循环
- **凶手**：`ApiGuard3`（Approov 的 Android SDK，Java 类 `com.apiguard3.internal.C`）—— 注意：**APK 里没有 libapiguard3.so**，它的 native 部分是运行时解密 + mmap 出来的匿名 r-xp blob，maps 里只看到 `<anonymous:6cb65d4000>` 这种地址，没有 SO 路径
- **检测手段**：扫 `/proc/self/maps`，把自己那段匿名 r-xp 排除掉之后，发现还存在另一段 `r-xp` 区域 **没有任何 DSO 文件路径**（QBDI 翻译出的指令落在 `[anon:dalvik-LinearAlloc]`），随即构造一个特征化崩溃自杀
- **签名特征**：崩溃时 `pc=0x97c, sp=0, lr=0`，多个寄存器同时呈现 `0xb6a2897d` 和 `0x97c`，这是被人**主动构造**而非野指针踩出来的

---

## 1. 背景与目标

星巴克 App 用了多层壳：
- 一壳：`libDexHelper.so`（Bangcle/邦邦壳），负责解密第二层
- 二壳：`libcfbe0b.so`，运行时被 `libDexHelper` 解出来释放到 `[anon:dalvik-LinearAlloc]` 区域
- 此外还能看到：`libdexjni.so`、`libsbux-security.so`、`libpns-2.14.19-*.so` 等业务/检测 SO，主段都是 `rwxp`

要 trace 的目标函数在 `libcfbe0b.so + 0xFED4`。

工具栈：
- **xj3**（stealth frida fork，替换标准 frida-server，路径 `/data/local/tmp/xj3`）—— 标准 frida-server 在这种壳面前秒被识别
- **bypass_bangbang.js** —— 已知绕过 `libDexHelper.so` 一壳的检测（patch kill/exit/detection 函数 + 擦 `/proc/*/maps` 中的 frida 字段）
- **xfQTrace** —— 注入到目标进程后，对指定函数做 QBDI 指令级 trace，开 `sync_flush=true` 时每条指令立刻写盘并打 logcat

---

## 2. 操作流程

```bash
# 1. 编译 xfQTrace 引擎 SO
./gradlew :nativelib:assembleRelease

# 2. 一键 push + 注入 + 等 trace 完成 + pull + 解压
python example_trace/demo_trace.py \
       -p com.starbucks.cn \
       --bypass bangbang \
       --script example_trace/星巴克_trace.js
```

`星巴克_trace.js` 的关键配置：

```js
const CONFIG = {
    target_so: "libcfbe0b.so",
    engine_path: "/data/data/com.starbucks.cn/files/libxfqtrace.so",
    qtrace: {
        hook_backend: 1,
        target: { offset: 0xFED4 },
        output_format: 0,
        compression: { enable: false, level: 0 },
        sync_flush: true,         // 调试模式：每条指令立即落盘 + 打 logcat
        max_traces: 1,
        hook_format: { args: "cstr", ret: "hex", naming_source: 0, naming_index: 0 },
    },
};
```

启动顺序的关键点：必须等 `bypass_bangbang.js` 把 `libDexHelper.so` 那层检测干掉之后，再 `dlopen` xfQTrace 引擎、再 `xfqtrace_configure/start`，否则一壳直接把进程 kill 掉。

```js
if (typeof globalThis.onBangbangReady === 'function') {
    globalThis.onBangbangReady(start);
} else {
    log("WARNING: bypass_bangbang.js not loaded");
    start();
}
```

---

## 3. 现象：App 崩溃 → 自动重启 → 死循环

注入完成后，logcat 在 `xfQTrace.sync` tag 下狂打指令日志。看着像在正常工作，但是：

- 大约 1450 条指令之后，trace 戛然而止
- App 进程消失
- zygote 立刻把它拉起来
- 拉起来后又跑到同一位置崩溃
- ……

很明显不是 trace 自己出 bug，而是 **app 主动自杀**。

---

## 4. 证据链

### 4.1 trace 在哪一步停的？

抓最后几条 sync 日志：

```
[anon 0x1453bc] 0x6f8eaed3bc: "mov x0, x19" ; x19=0x7066a473f0  => x0=0x7066a473f0
[anon 0x1453c0] 0x6f8eaed3c0: "ldr x8, [x19]" ; x19=0x7066a473f0  => x8=0x6fa2e0c7b8
[anon 0x1453c4] 0x6f8eaed3c4: "mov x1, x22" ; x22=0x6f8eb1c83c  => x1=0x6f8eb1c83c
[anon 0x1453c8] 0x6f8eaed3c8: "ldr x8, [x8, #0x30]" ; x8=0x6fa2e0c7b8  => x8=0x6fa2be206c

=============== -> call: JNIEnv::FindClass("com/apiguard3/internal/C") =================
[anon 0x1453cc] 0x6f8eaed3cc: "blr x8" ; x8=0x6fa2be206c sp=0x6c76c5ab70
```

最后一条 trace 到的指令是 `blr x8`，调用的是 `JNIEnv::FindClass("com/apiguard3/internal/C")`。

trace 输出到这里就断了 —— **不是 trace 自己出错，是 FindClass 走进 ApiGuard3 静态初始化里之后就回不来了**。

### 4.2 `com.apiguard3.internal.C` 是什么？为什么 maps 里没有 libapiguard3.so？

`apiguard3` 是 [CriticalBlue Approov](https://approov.io/) 的 Android SDK 包名，是独立于壳的 API runtime attestation 方案。

**第一个反常点**：app 加载的 SO 列表里**没有任何 `libapiguard3.so` / `libag3.so`**。从 `/proc/<pid>/maps` 提取这个 app 自己的 SO 加载列表：

```
/data/app/.../lib/arm64/libDexHelper.so
/data/app/.../lib/arm64/libcfbe0b.so
/data/app/.../lib/arm64/libdexjni.so
/data/app/.../lib/arm64/libe763.so
/data/app/.../lib/arm64/libmmkv.so
/data/app/.../lib/arm64/libpns-2.14.19-LogOnlineStandardCuumRelease_alijtca_plus.so
/data/app/.../lib/arm64/librc_tool.so
/data/app/.../lib/arm64/libsbux-security.so
```

8 个 SO，没有一个名字带 `apiguard` 或 `ag3`。APK 的 `lib/arm64/` 下也找不到。

**第二个反常点**：tombstone 却清楚显示有两条以 ApiGuard3 命名的线程：

```
pid: 23450, tid: 23506, name: APIGuard3Backgr  >>> com.starbucks.cn <<<
pid: 23450, tid: 23694, name: APIGuard3Um      >>> com.starbucks.cn <<<
```

而且 `APIGuard3Backgr` 线程的栈一路从 Java 调到 native：

```
#10 art_quick_generic_jni_trampoline+148
#11 nterp_helper+5648
#12 com.apiguard3.internal.C.getSharedInstance+142   ← Java
#13 nterp_helper+3924
#14 com.apiguard3.internal.C$3.run+600                ← Java
#15 android.os.Handler.dispatchMessage+84
...
```

注意 `art_quick_generic_jni_trampoline` 上面那段 native 栈帧：

```
#03 pc 0x000000000003c5d8  <anonymous:6cb65d4000>
#04 pc 0x000000000016654c  <anonymous:6cb65d4000>
#05 pc 0x0000000000142a84  <anonymous:6cb65d4000>
#06 pc 0x0000000000164b38  <anonymous:6cb65d4000>
#07 pc 0x00000000000f0128  <anonymous:6cb65d4000>
#08 pc 0x000000000015908c  <anonymous:6cb65d4000>
#09 pc 0x0000000000145bb0  <anonymous:6cb65d4000>
```

**全部 7 帧都在 `<anonymous:6cb65d4000>`，没有任何 SO pathname**。在 maps 里找 `6cb65d4000` 这个地址 —— 也没有，说明它是 ApiGuard3 启动后才动态 mmap 出来的，且生命周期短到 maps dump 之前已经被换/释放过一轮。

也就是说：

> **ApiGuard3 的 native 检测引擎根本不以 SO 文件的形式存在**。它的 native blob 是被 Java 层 `com.apiguard3.internal.C` 在运行时**解密 + `mmap` 一段匿名可执行内存 + 把入口 dlsym 化**装进去的，APK 里压根没有它。

这跟 QBDI 代码缓存的形态是**镜像对称**的：
- QBDI 代码缓存：r-xp + 无 DSO + 是我们做的
- ApiGuard3 native blob：r-xp + 无 DSO + 是它做的

它检测的就是"**maps 里出现了我以外的、其它没有 DSO pathname 的 r-xp 段**"。

### 4.3 关键证据：trace PC 落在 `[anon]` 段

注意那条最后的 `blr x8`：

```
[anon 0x1453cc] 0x6f8eaed3cc: "blr x8"
```

PC 是 `0x6f8eaed3cc`。前缀 `[anon ...]` 是 xfQTrace 的 `ModuleCatalog` 反查不到 module 名时的 fallback —— **说明这段地址不属于任何已加载的 ELF/SO**。

去查这段地址在 `/proc/self/maps` 里的归属：

```
6f8e9be000-6f8eb1e000 r-xp 00000000 00:00 0  [anon:dalvik-LinearAlloc]
```

`0x6f8eaed3cc` 落在 `6f8e9be000-6f8eb1e000` 中间，这一段是 `[anon:dalvik-LinearAlloc]` —— **没有任何 DSO 文件路径关联**，但拥有可执行权限（`r-xp`）。

这就是 `libDexHelper` 把二壳 `libcfbe0b.so` 解出来之后**塞到匿名内存里执行**的结果。

对正常应用来说，这种"代码运行在 r-xp 但没 DSO"的情况几乎不存在。对反检测系统来说，这是一个非常强的信号。

### 4.4 崩溃签名：构造性自杀，不是野指针

抓到 tombstone 的核心寄存器（来自前一段会话的现场）：

```
pc   0x000000000000097c
sp   0x0000000000000000
lr   0x0000000000000000
x1   0xb6a2897d
x8   0xb6a2897d
x9   0x000000000000097c
x10  0xb6a2897d
x12  0x000000000000097c
x19  0xb6a2897d
```

这种 register pattern 不是堆栈被踩坏的样子。野指针崩溃的特征是 **某一两个寄存器是垃圾值，其它的还合理**。这里是：

- `pc / x9 / x12` 三个寄存器同步出现 `0x97c`
- `x1 / x8 / x10 / x19` 同步出现 `0xb6a2897d`
- `sp / lr` 都是 0

这只能是被一段类似下面的 stub 主动构造：

```asm
mov x9,  #0x97c
mov sp,  xzr
mov lr,  xzr
mov x1,  #0xb6a2897d   ; 或 ldr 一个常量池值
...
br  x9                  ; 跳到 0x97c (一个保证 SIGSEGV 的地址)
```

`0xb6a2897d` 和 `0x97c` 都是固定 sigil，方便防护方在事后从崩溃日志里反查 "这是我自己干的"，区别于正常 crash。

### 4.5 反取证证据：被砍断的 backtrace + 完全一致的"递归栈"

tombstone 里崩溃线程的 `backtrace:` 段长这样：

```
backtrace:
      #00 pc 000000000000097c  <unknown>
      #01 pc 0000000000000000  <unknown>
```

只有 **2 帧**，而且 `#01 pc=0` 直接 `<unknown>`。

这是因为攻击者在跳到 `0x97c` 之前显式做了：

```asm
mov sp, xzr        ; sp=0
mov lr, xzr        ; lr=0
br  x9             ; 跳到 0x97c
```

`sp=0 / lr=0` 不是崩溃后的副作用，是**构造时的初始条件**。Android 的 unwinder 一看 `lr=0` 就立刻停止回溯 —— 所以 tombstone 永远拿不到调用方是谁，**取证链条在第 1 帧就被砍断**。

把这条 backtrace 和别的崩溃线程对比就更明显了。同一个 tombstone 里，正常的 Signal Catcher 线程的栈是这样的：

```
#00 pc 0x...  /apex/com.android.runtime/lib64/bionic/libc.so (__rt_sigtimedwait+8)
#01 pc 0x...  /apex/com.android.art/lib64/libart.so (...)
#02 pc 0x...  /apex/com.android.art/lib64/libart.so (...)
... 二十多帧，一路回溯到 __libc_init / __start_thread
```

正常线程的栈帧能回溯 20 多层一路到 `__libc_init`；崩溃线程偏偏只有 2 帧 —— **这是被设计成不可回溯的，不是偶然**。

更进一步，看 zygote 反复拉起进程的过程：

| 第 N 次重启 | crash pc | crash lr | crash sp | 主线程 backtrace |
|----|----|----|----|----|
| 第 1 次 | `0x97c` | `0` | `0` | 2 帧死栈 |
| 第 2 次 | `0x97c` | `0` | `0` | 2 帧死栈 |
| 第 3 次 | `0x97c` | `0` | `0` | 2 帧死栈 |
| ... | ... | ... | ... | ... |

每次拉起、每次崩、每次崩在**完全一样的位置、完全一样的寄存器签名、完全一样的 2 帧栈**。如果是野指针/堆损坏 / UAF 这类真实 bug，pc 会在不同地址漂移，寄存器值会随机化（堆地址、栈地址受 ASLR 影响每次启动都不同）。这里 `pc=0x97c / x1=0xb6a2897d` 这两个常量在 N 次重启中保持不变 —— **能跨进程稳定的只有指令立即数（imm），也就是说这两个值是被一段类似 `mov x9, #0x97c; movk x1, #0xb6a2; movk x1, #0x897d, lsl#16` 的代码常量化注入进去的**，不是从内存里读出来的。

所以这个递归式重启循环不是 "app 一直在尝试启动失败"，而是 ApiGuard3 每次起来都重新跑一遍检测，每次都发现 maps 里有 `r-xp` 没 DSO 的段（QBDI 代码缓存仍在），于是每次都触发同一段 sigil 化的自杀 stub。

### 4.7 触发链复盘

把上面所有点串起来：

1. xfQTrace 的 QBDI VM 把 `libcfbe0b.so` 翻译成 patched 指令，写入 QBDI 的代码缓存（落在 `[anon:dalvik-LinearAlloc]` 区域，因为 QBDI 是用 mmap 申请的匿名可执行内存）
2. 被 trace 的目标函数走到一处 JNI 调用 `FindClass("com/apiguard3/internal/C")`
3. ApiGuard3 类被首次加载 → `<clinit>` 触发 ApiGuard3 自带的 native loader：在 Java 层把一段加密 blob 解密 + `mmap` 成 r-xp + 通过类似 `JNIEnv::RegisterNatives` 把入口绑到 Java 方法上（这一段在 Java 层，过 `art_quick_generic_jni_trampoline` 后进入 `<anonymous:6cb65d4000>`）
4. ApiGuard3 native 初始化函数扫 `/proc/self/maps`
5. 它知道自己那段匿名 r-xp 的范围（毕竟是它自己 mmap 的），于是**把自己排除掉之后**还能找到一段 r-xp 没 DSO 的内存（`6f8e9be000-6f8eb1e000 [anon:dalvik-LinearAlloc]`，QBDI 代码缓存），且当前**调用栈 PC 就来自这段**
6. 调度到一段 sigil 化的崩溃 stub，pc=`0x97c` / x1=`0xb6a2897d` / sp=`0` / lr=`0`，进程 SIGSEGV
7. zygote 重启 → 重新跑到 `FindClass` → 重新触发 → 死循环

---

## 5. 为什么 `bypass_bangbang.js` 没救？

`bypass_bangbang.js` 只针对一壳 `libDexHelper.so`：
- patch 它内部的 `kill_wrap` / `exit_wrap` / `detection_log` 直接 `mov x0,#0; ret`
- hook 它内联汇编的 `svc openat/read/close`，从 `/proc/*/maps` 读出来的内容里把 `frida|gum|gadget|...` 行擦掉
- hook libc 的 `kill/tgkill/abort/_exit/exit`

但 ApiGuard3 是**完全独立于壳的二级检测**，且形态也不一样：
- 它的 native 部分**不是 SO**（APK 里也没有 libapiguard3.so / libag3.so），是 `com.apiguard3.internal.C` 在 Java 层运行时解密出来再 `mmap` 的匿名 r-xp blob —— 我们没有"hook 它的 export"这种入口可言，因为它本身就没 export 表
- 它扫 maps 走自己那段 blob 的代码，不经过 libDexHelper 的 svc wrapper，bypass_bangbang 那一套 patch 完全不覆盖
- 它的检测条件不是 "存在 frida 字符串"，而是 "**存在我以外的、没有 DSO pathname 的 r-xp 段**"，bypass_bangbang 的 maps 擦字段逻辑只擦 `frida/gum/gadget` 这些字符串，**对 `[anon:dalvik-LinearAlloc]` 没动**
- 它的崩溃 stub 把 lr/sp 清零，unwinder 回溯不到调用方 —— 无法靠崩溃栈定位 stub 物理位置

所以 bypass_bangbang 完全不覆盖这个面。这是个独立的对抗层。

---

## 6. 对抗思路（思考 → 排序 → 具体怎么落地）

定位清楚之后，对抗的可行路径其实是分层的：从"在 maps 这一层骗它"到"在它的检测代码本身上动刀"。我按从轻到重排，每条都讲清"为什么可能行"和"为什么可能不行"。

### 思路 A：在 maps 这一层骗它（伪造 pathname）

**做法**：hook `open/openat("/proc/self/maps", ...)` + 后续 `read`，把 QBDI 代码缓存所在的 `[anon:dalvik-LinearAlloc]` 那一行重写成一个看起来合法的 SO 路径，比如挂到 `/system/lib64/libart.so` 末尾或 `/apex/com.android.art/lib64/libart.so` 上。

**为什么可能行**：检测核心条件是 "r-xp + 无 pathname"，把 pathname 字段填上看似合理的值即可绕过最朴素的检测。

**为什么可能不行**：
1. ApiGuard3 不一定走 `open("/proc/self/maps")`。它的 native blob 可能直接读 `/proc/self/smaps` / `/proc/self/maps_files` / 甚至直接 `syscall` 绕开 libc，需要先确认它读 maps 走哪条路径
2. 它可能进一步交叉验证：对每个 r-xp 段读 ELF magic（`0x7F 'E' 'L' 'F'`）；libart.so 头确实是 ELF magic，但 QBDI 代码缓存头不是。这种交叉验证就靠改 maps 字段过不去
3. 它可能比对 `dlinfo()` / `link_map` 链表 —— 那里只列出真正 dlopen 加载的 SO，伪造的 maps pathname 不会出现在链表里，对不上就报警

**落地优先级**：先做，因为成本最低；做完用对抗效果验证它的检测深度有多深。

### 思路 B：把 QBDI 代码缓存挂成有名文件映射

**做法**：用 `memfd_create("libart_compiled.so", 0)` + `ftruncate` + `mmap(MAP_SHARED|PROT_EXEC, fd)` 给 QBDI 分配的代码缓存挂一个 fd 路径。这样 maps 里那一行就会是 `/memfd:libart_compiled.so (deleted)` 或 `/memfd:libart_compiled.so` 而不是 `[anon:dalvik-LinearAlloc]`。

**为什么可能行**：
1. `memfd:` 路径在 Android 13 上是合法的内核内存对象路径，inode 也非 0
2. 系统中真实的 ART JIT 代码缓存就有用 memfd 的实践
3. 比单纯改 maps 字段更"自顶向下"地解决，maps 看起来"自然"，不需要每次读 maps 都 hook

**为什么可能不行**：
1. 需要改 QBDI 内部的 mmap 调用（QBDI 是 vendor 进来的第三方代码，patch 会绑定一份本地 fork，维护成本上升）
2. 仍然过不了 ELF magic 校验和 link_map 校验
3. ApiGuard3 可能直接 ban 掉所有 `/memfd:*` 路径，因为正常 app 几乎不会有这种映射

**落地优先级**：在 A 失败但 ELF magic 还没成为问题时尝试。

### 思路 C：让 QBDI 代码缓存"伪装成 ELF"

**做法**：在 QBDI 申请代码缓存的内存最前面 64 字节人工写一个合法但内容空的 ARM64 ELF header（`e_ident` + `e_type=ET_DYN` + `e_machine=EM_AARCH64`），让做 ELF magic 校验的检测器误判这是个合法 SO。

**为什么可能行**：搭配思路 A/B，能同时过 maps pathname 检测 + ELF magic 校验。

**为什么可能不行**：
1. ApiGuard3 可能进一步走 `dl_iterate_phdr` 遍历真正的 link_map，那里只有 `dlopen` 注册过的 SO，伪造 ELF header 出现在 maps 里但不在 link_map 里，反而成了更强的"可疑"信号
2. 改 QBDI 内部的代码缓存布局，需要确保 ELF header 区域的 64 字节不会被 QBDI 当成可执行指令使用 —— 通常 QBDI 代码缓存有 prologue 区域，写在 prologue 之前的 padding 里相对安全

**落地优先级**：跟 A/B 配合使用。

### 思路 D：不在 maps 层博弈，直接 patch ApiGuard3 检测函数

**做法**：等 ApiGuard3 的 native blob 被解密 + mmap 出来之后，直接定位它的检测函数 / 自杀 stub 位置，把它 patch 成 `mov x0, #0; ret` 或者 NOP 化。

**为什么可能行**：从根上断掉检测，不管它将来加什么交叉验证都没用。

**为什么可能不行**：
1. ApiGuard3 的 native blob 不是固定 SO，**每次启动 mmap 出来的基址不一样**，offset 不能像 bypass_bangbang 那样硬编码
2. 解密后的指令里没有可读符号、没有 export 表，需要靠 pattern matching / 控制流签名定位检测函数
3. 它可能多份 blob 互相校验完整性（self-check），patch 一处会被另一处发现

**怎么找它**：
- 在 tombstone 里看到 ApiGuard3 native 栈帧从 `<anonymous:6cb65d4000>` 一路上 7 层。具体做法：
  1. hook `mmap` / `mprotect`，监听任何"先 PROT_READ|PROT_WRITE 后 PROT_EXEC"或者 `MAP_ANONYMOUS|PROT_EXEC` 的调用，记录基址 + 大小
  2. 等 `JNIEnv::FindClass("com/apiguard3/internal/C")` 触发后的第一段 anon r-xp 就是它
  3. 在它的入口设个断点 / Stalker，等触发检测时单步出来，定位"扫完 maps 之后那段 cmp + b stub" 的代码
  4. 把那条 cmp 之后的 b 改成无条件 nop

**落地优先级**：A/B/C 都失败之后的根治方案，但工作量最大。

### 思路 E：换 hook 模式（短期 workaround）

**做法**：xfQTrace 不走 QBDI VM，而是走 inline patching（直接在目标函数的指令流里打 ldr/br 跳转回 trampoline），不依赖匿名可执行内存。

**为什么可能行**：inline patch 修改的是已加载 SO 自己的 `r-xp` 区域，不会引入新的 anon r-xp 段，规避检测。

**为什么可能不行**：
1. inline patching 的覆盖率/灵活性远不如 VM 模式（不能跨指令统计、不能改写控制流、对 cb_z/tb_z 这种短跳无能为力）
2. patch 会改动目标 SO 的 r-xp 区域，触发壳/检测的"自校验"——不是没人检查这个，而是 ApiGuard3 暂时不查
3. 用户的核心诉求是"看到每条指令的副作用"，换模式之后等于阉割了产品

**落地优先级**：最后的应急手段，不作为常规方案。

### 推荐路径

```
1. 先做 A：hook maps 读取，把 QBDI 代码缓存那行 pathname 伪造成 libart.so
   ↓ 看 ApiGuard3 是否还崩
2. 还崩 → 加上 C：在 QBDI 代码缓存头部填合法 ELF header
   ↓
3. 还崩 → 上 B：改 QBDI 用 memfd_create 而不是 mmap MAP_ANONYMOUS
   ↓
4. 还崩 → 说明它已经在做 link_map / dl_iterate_phdr 级别的强校验，
            必须走 D：动态定位 ApiGuard3 native blob → patch 检测函数
```

每一步都先做最简单的，崩了再升级，不要直接跳到 D。每一步都能产出独立可发的对抗结论。

---

## 7. 复现要点

环境：
- Pixel 系列（root），Android 13
- xj3（stealth frida fork）部署到 `/data/local/tmp/xj3`
- 标准 frida-server 在这个 app 上**直接秒杀**，必须用 xj3

命令：
```bash
python example_trace/demo_trace.py \
       -p com.starbucks.cn \
       --bypass bangbang \
       --script example_trace/星巴克_trace.js
```

观察：
```bash
adb logcat -s xfQTrace.sync:D
```

崩溃证据：
```bash
adb logcat -b crash | grep -E "pid|signal|pc|x[0-9]+" | head -50
```

trace 末尾片段：
```bash
ls example_trace/trace_logs/com.starbucks.cn_*/
```
查看最后 200 行，定位到 `JNIEnv::FindClass("com/apiguard3/internal/C")`。

---

## 8. 总结

这次最大的收获不是"绕不过去"，而是**搞清楚了它是怎么发现我的**。

- 反检测系统不是黑盒，每一次崩溃都留有签名 —— `pc=0x97c, x1=0xb6a2897d, sp=0, lr=0` 这种"工整"的现场，必然是构造，不是事故
- 一旦知道了检测原理是 "**maps 里有 r-xp 没 DSO**"，对策就从"瞎猜哪里被发现"变成了"伪造 maps 字段 / 给代码缓存挂名"这种具体可执行的工作
- ApiGuard3 / Approov 是独立于壳的二级检测，标准的 bypass 套路（kill/exit/log patch + maps 擦字符串）不足以覆盖

下一步是写 `bypass_apiguard3.js`，并且尝试给 QBDI 的代码缓存伪造一个合法的 maps pathname。

---

*配图建议*：
- 图1：trace 末尾 `FindClass("com/apiguard3/internal/C")` 截图
- 图2：`/proc/self/maps` 中 `[anon:dalvik-LinearAlloc]` 那一行高亮
- 图3：tombstone 寄存器签名（`0x97c` / `0xb6a2897d` 高亮）
- 图4：app 重启循环的 logcat
