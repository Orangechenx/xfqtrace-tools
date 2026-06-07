// bypass_anti_debug.js — 通用 Android anti-debug / anti-frida 绕过
// 目标：先于 trace 主脚本加载，尽量降低 ptrace、/proc、线程名、Frida 字符串、自杀路径对注入的干扰。

(function () {
    if (globalThis.__xfq_anti_debug_loaded) return;
    globalThis.__xfq_anti_debug_loaded = true;

    const TAG = '[anti-debug]';
    const log = (msg) => console.log(`${TAG} ${msg}`);
    const warn = (msg) => console.warn(`${TAG} ${msg}`);

    const MY_PID = Process.id;
    const LETHAL_SIGS = new Set([5, 6, 9, 11, 15, 31]);
    const SUSPICIOUS_RE = /frida|gum-js-loop|gum-js|gmain|gdbus|linjector|re\.frida|frida-agent|frida-server|hluda|r0gson|magisk|zygisk|lsposed|xposed|substrate|debuggerd|gdbserver/i;
    const PROC_RE = /\/proc\/(self|\d+)\/(status|maps|task|cmdline|comm|stat|fd|net\/tcp|net\/unix)/;

    function findExport(name) {
        try { return Module.findExportByName(null, name) || Module.findExportByName('libc.so', name); } catch (_) { return null; }
    }

    function readCStringSafe(ptrValue) {
        try {
            if (!ptrValue || ptrValue.isNull()) return '';
            return ptrValue.readCString() || '';
        } catch (_) {
            return '';
        }
    }

    function isSuspiciousText(text) {
        return Boolean(text && SUSPICIOUS_RE.test(text));
    }

    function isProcProbePath(path) {
        return Boolean(path && PROC_RE.test(path));
    }

    function scrubText(text) {
        if (!text) return text;
        return text
            .split('\n')
            .filter((line) => !SUSPICIOUS_RE.test(line))
            .map((line) => line.replace(/TracerPid:\s*\d+/i, 'TracerPid:\t0'))
            .join('\n');
    }

    function scrubBuffer(buffer, length, retval) {
        if (length <= 0 || !buffer || buffer.isNull()) return;
        try {
            const before = buffer.readCString(length);
            if (!before || (!SUSPICIOUS_RE.test(before) && !/TracerPid:\s*[1-9]\d*/i.test(before))) return;
            const after = scrubText(before);
            buffer.writeUtf8String(after);
            const written = Math.min(length, after.length);
            for (let i = written + 1; i < length; i += 1) buffer.add(i).writeU8(0);
            if (retval) retval.replace(ptr(written));
            log('已清理 /proc 读取结果中的调试特征');
        } catch (_) {}
    }

    function hookReturnZero(name, retType, argTypes, matcher) {
        const addr = findExport(name);
        if (!addr) return;
        try {
            const original = new NativeFunction(addr, retType, argTypes);
            Interceptor.replace(addr, new NativeCallback(function () {
                const args = Array.prototype.slice.call(arguments);
                try {
                    if (matcher && matcher(args)) return 0;
                    return original.apply(null, args);
                } catch (_) {
                    return 0;
                }
            }, retType, argTypes));
            log(`已安装 ${name} 绕过`);
        } catch (e) {
            warn(`${name} 绕过失败: ${e}`);
        }
    }

    function installPtraceBypass() {
        hookReturnZero('ptrace', 'int', ['int', 'int', 'pointer', 'pointer'], function (args) {
            const request = args[0].toInt32();
            if (request === 0) log('拦截 ptrace(PTRACE_TRACEME)');
            return true;
        });

        const syscall = findExport('syscall');
        if (!syscall) return;
        try {
            Interceptor.attach(syscall, {
                onEnter(args) {
                    const nr = args[0].toInt32();
                    // arm64 __NR_ptrace = 117；其他架构保留常见值，命中才改返回。
                    this.isPtrace = nr === 117 || nr === 26;
                },
                onLeave(retval) {
                    if (this.isPtrace) {
                        retval.replace(ptr(0));
                        log('拦截 syscall(ptrace)');
                    }
                }
            });
            log('已安装 syscall(ptrace) 绕过');
        } catch (e) {
            warn(`syscall 绕过失败: ${e}`);
        }
    }

    function installPrctlBypass() {
        const prctl = findExport('prctl');
        if (!prctl) return;
        try {
            Interceptor.attach(prctl, {
                onEnter(args) {
                    const option = args[0].toInt32();
                    // PR_SET_DUMPABLE=4，阻止把进程改成不可 dump，避免影响后续 attach/trace。
                    if (option === 4 && args[1].toInt32() === 0) {
                        args[1] = ptr(1);
                        this.changed = true;
                    }
                },
                onLeave(retval) {
                    if (this.changed) retval.replace(ptr(0));
                }
            });
            log('已安装 prctl 绕过');
        } catch (e) {
            warn(`prctl 绕过失败: ${e}`);
        }
    }

    function installSelfKillBypass() {
        ['kill', 'tkill', 'tgkill'].forEach((name) => {
            const addr = findExport(name);
            if (!addr) return;
            try {
                Interceptor.attach(addr, {
                    onEnter(args) {
                        const targetPid = args[0].toInt32();
                        const sigIndex = name === 'tgkill' ? 2 : 1;
                        const sig = args[sigIndex].toInt32();
                        if ((targetPid === MY_PID || targetPid === 0) && LETHAL_SIGS.has(sig)) {
                            args[0] = ptr(0x7fffffff);
                            log(`拦截自杀信号 ${name}(pid=${targetPid}, sig=${sig})`);
                        }
                    }
                });
                log(`已安装 ${name} 自杀拦截`);
            } catch (e) {
                warn(`${name} 自杀拦截失败: ${e}`);
            }
        });

        const terminators = [
            { name: 'raise', ret: 'int', args: ['int'], value: 0 },
            { name: 'abort', ret: 'void', args: [], value: undefined },
            { name: '_exit', ret: 'void', args: ['int'], value: undefined },
            { name: 'exit', ret: 'void', args: ['int'], value: undefined },
        ];
        terminators.forEach((item) => {
            const addr = findExport(item.name);
            if (!addr) return;
            try {
                Interceptor.replace(addr, new NativeCallback(function () {
                    log(`拦截 ${item.name}`);
                    return item.value;
                }, item.ret, item.args));
                log(`已安装 ${item.name} 拦截`);
            } catch (e) {
                warn(`${item.name} 拦截失败: ${e}`);
            }
        });
    }

    function installProcReadBypass() {
        const taggedFds = new Set();

        function tagFd(retval, path) {
            const fd = retval.toInt32();
            if (fd >= 0 && (isProcProbePath(path) || isSuspiciousText(path))) {
                taggedFds.add(fd);
                log(`标记可疑 fd=${fd}: ${path}`);
            }
        }

        const open = findExport('open');
        if (open) {
            try {
                Interceptor.attach(open, {
                    onEnter(args) { this.path = readCStringSafe(args[0]); },
                    onLeave(retval) { tagFd(retval, this.path); }
                });
            } catch (e) { warn(`open hook 失败: ${e}`); }
        }

        const openat = findExport('openat');
        if (openat) {
            try {
                Interceptor.attach(openat, {
                    onEnter(args) { this.path = readCStringSafe(args[1]); },
                    onLeave(retval) { tagFd(retval, this.path); }
                });
            } catch (e) { warn(`openat hook 失败: ${e}`); }
        }

        const read = findExport('read');
        if (read) {
            try {
                Interceptor.attach(read, {
                    onEnter(args) {
                        this.fd = args[0].toInt32();
                        this.buf = args[1];
                    },
                    onLeave(retval) {
                        const n = retval.toInt32();
                        if (n > 0 && taggedFds.has(this.fd)) scrubBuffer(this.buf, n, retval);
                    }
                });
            } catch (e) { warn(`read hook 失败: ${e}`); }
        }

        const close = findExport('close');
        if (close) {
            try {
                Interceptor.attach(close, { onEnter(args) { taggedFds.delete(args[0].toInt32()); } });
            } catch (e) { warn(`close hook 失败: ${e}`); }
        }

        ['access', 'stat', 'lstat', 'fopen'].forEach((name) => {
            const addr = findExport(name);
            if (!addr) return;
            try {
                Interceptor.attach(addr, {
                    onEnter(args) {
                        const path = readCStringSafe(args[0]);
                        // 不直接重定向 /proc/maps/status：xfqtrace 引擎也依赖 maps。
                        // /proc 内容统一在 open/read 路径里按 fd 清洗，只有明显 Frida 路径才改到 /dev/null。
                        if (isSuspiciousText(path) && !isProcProbePath(path)) {
                            args[0] = Memory.allocUtf8String('/dev/null');
                            log(`重定向 ${name}: ${path} -> /dev/null`);
                        }
                    }
                });
            } catch (e) { warn(`${name} hook 失败: ${e}`); }
        });

        // 默认安全档不 hook readlink，避免影响 Frida/xfqtrace 模块路径解析。
        log('已安装 /proc 读取清理');
    }

    // 注意：默认安全档不 hook strstr/strcmp。
    // 这些 libc 字符串比较函数会被 Frida 和 xfqtrace 自身大量使用，
    // 全局替换容易导致 xfqtrace_start 崩溃。强力字符串隐藏应拆成单独 bypass。
    // 默认安全档不 hook dlopen 家族。
    // xfqtrace 自己依赖 dlopen / android_dlopen_ext 进行引擎装载，
    // 在这些入口上再叠 Interceptor 会与 xfqtrace_start 产生冲突。

    function installJavaBypass() {
        if (!Java.available) return;
        Java.perform(function () {
            try {
                const Debug = Java.use('android.os.Debug');
                Debug.isDebuggerConnected.implementation = function () { return false; };
                Debug.waitingForDebugger.implementation = function () { return false; };
                log('已安装 Java Debug 绕过');
            } catch (e) { warn(`Java Debug 绕过失败: ${e}`); }

            // 默认安全档不 hook Runtime.exec / ProcessBuilder；
            // 这些 API 可能被目标 App 和 tracing runtime 正常使用，强拦截拆到单独 bypass。
        });
    }

    installPtraceBypass();
    installPrctlBypass();
    installSelfKillBypass();
    installProcReadBypass();
    installJavaBypass();

    log('anti-debug bypass armed');
})();
