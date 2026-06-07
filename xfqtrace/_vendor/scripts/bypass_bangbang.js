// bypass_bangbang.js — 通用 Bangcle/邦邦/壳 anti-frida 绕过
//
// 用法：
//   - frida -l bypass_bangbang.js -l demo_trace.js  (CLI 拼接)
//   - 或在 python: bypass_pre_script = 读取本文件，注入到 session.create_script 之前
//
// 提供：tryInstallBangbangBypass()  —— 等 libDexHelper.so 出现就 patch
//      onBypassReady(cb)            —— 注册一次性回调，bypass 完成后触发
//
// 副作用：
//   - patch libDexHelper.so 内 kill/exit/detection 三处函数 → 直接 ret 0
//   - 拦截 libDexHelper 内联 svc openat/read/close（读 maps 时擦掉 frida 行）
//   - hook libc kill/tgkill/tkill：发给自身 SIGKILL/SIGABRT/SIGSEGV/SIGTERM 一律改 PID
//   - replace abort/_exit/exit → 直接返回 0
//
// 不做：trace。trace 配置/启动放在主脚本里，本脚本只把检测/自杀路径关掉。

(function () {
    if (globalThis.__bangbang_loaded) return;
    globalThis.__bangbang_loaded = true;

    const log = (msg) => console.log(`[bangbang] ${msg}`);

    let bypassDone = false;
    const _readyCbs = [];

    function fireReady() {
        while (_readyCbs.length) {
            try { _readyCbs.shift()(); } catch (e) { log('ready cb threw: ' + e); }
        }
    }

    globalThis.onBangbangReady = function (cb) {
        if (bypassDone) {
            try { cb(); } catch (e) { log('ready cb threw: ' + e); }
        } else {
            _readyCbs.push(cb);
        }
    };

    globalThis.isBangbangReady = function () { return bypassDone; };

    function patchReturnZero(addr, label) {
        Memory.protect(addr, 8, 'rwx');
        // mov x0, #0  ;  ret
        addr.writeByteArray([0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6]);
        log(`patched ${label} @ ${addr}`);
    }

    function installNativeBypass(base) {
        // 这些偏移目前与 com.starbucks.cn 的 libDexHelper.so 对齐
        const kill_wrap_off       = 0x386D0;
        const exit_wrap_off       = 0x1091DC;
        const detection_log_off   = 0x2DDA0;
        const sc_openat_off       = 0x1091C4;
        const sc_read_off         = 0x1091B8;
        const sc_close_off        = 0x1091D0;
        const at = (off) => base.add(off);

        try { patchReturnZero(at(kill_wrap_off),     'kill wrapper'); } catch (e) { log('kill patch failed: ' + e); }
        try { patchReturnZero(at(exit_wrap_off),     'exit wrapper'); } catch (e) { log('exit patch failed: ' + e); }
        try { patchReturnZero(at(detection_log_off), 'detection logger'); } catch (e) { log('det patch failed: ' + e); }

        // /proc/*/maps 擦字段
        const mapsFds = new Set();
        try {
            Interceptor.attach(at(sc_openat_off), {
                onEnter(args) {
                    try {
                        const path = args[1].readUtf8String();
                        if (path && path.includes('/proc/') && path.includes('maps')) this._tag = true;
                    } catch (_) {}
                },
                onLeave(retval) {
                    if (this._tag && retval.toInt32() > 0) {
                        mapsFds.add(retval.toInt32());
                        log(`tagged maps fd ${retval.toInt32()}`);
                    }
                }
            });
            Interceptor.attach(at(sc_read_off), {
                onEnter(args) {
                    this._fd = args[0].toInt32();
                    this._buf = args[1];
                },
                onLeave(retval) {
                    const n = retval.toInt32();
                    if (n <= 0 || !mapsFds.has(this._fd)) return;
                    try {
                        let str = this._buf.readCString(n);
                        if (/frida|gum|gadget|linjector|hluda|sl16/i.test(str)) {
                            str = str.replace(/.*(?:frida|gum|gadget|linjector|hluda|sl16).*\n?/gi, '');
                            const enc = new TextEncoder().encode(str);
                            this._buf.writeByteArray(Array.from(enc));
                            for (let i = enc.length; i < n; i++) this._buf.add(i).writeU8(0);
                            retval.replace(ptr(enc.length));
                            log('scrubbed maps read');
                        }
                    } catch (_) {}
                }
            });
            Interceptor.attach(at(sc_close_off), {
                onEnter(args) { mapsFds.delete(args[0].toInt32()); }
            });
        } catch (e) {
            log('inline svc hook failed: ' + e);
        }

        // libc 自杀路径
        const MY_PID = Process.id;
        const LETHAL_SIGS = new Set([6, 9, 11, 15]);
        ['kill', 'tgkill', 'tkill'].forEach(name => {
            const fn = Module.findExportByName(null, name);
            if (!fn) return;
            try {
                Interceptor.attach(fn, {
                    onEnter(args) {
                        const target = args[0].toInt32();
                        const sig = args[name === 'tgkill' ? 2 : 1].toInt32();
                        if ((target === MY_PID || target === 0) && LETHAL_SIGS.has(sig)) {
                            args[0] = ptr(0x7FFFFFFF);
                        }
                    }
                });
            } catch (_) {}
        });
        ['abort', '_exit', 'exit'].forEach(name => {
            const fn = Module.findExportByName(null, name);
            if (!fn) return;
            try {
                Interceptor.replace(fn, new NativeCallback(() => 0, 'int', []));
            } catch (_) {}
        });

        log('native bypass installed');
    }

    function tryInstall() {
        const mod = Process.findModuleByName('libDexHelper.so');
        if (mod && !bypassDone) {
            bypassDone = true;
            installNativeBypass(mod.base);
            log('Bangbang bypass ready');
            fireReady();
            return true;
        }
        return false;
    }

    function monitorDlopen() {
        const dlopenNames = ['android_dlopen_ext', '__loader_android_dlopen_ext', 'dlopen'];
        dlopenNames.forEach(name => {
            const fn = Module.findExportByName(null, name);
            if (!fn) return;
            try {
                Interceptor.attach(fn, {
                    onEnter(args) {
                        try {
                            const path = args[0].readUtf8String();
                            if (path && path.includes('libDexHelper.so')) {
                                this._tag = true;
                                log(`dlopen("${path}")`);
                            }
                        } catch (_) {}
                    },
                    onLeave(_ret) {
                        if (this._tag) tryInstall();
                    }
                });
            } catch (_) {}
        });
    }

    globalThis.tryInstallBangbangBypass = tryInstall;

    // 自动启动
    tryInstall();
    monitorDlopen();
    log('Bangbang bypass armed (waiting for libDexHelper.so)');
})();
