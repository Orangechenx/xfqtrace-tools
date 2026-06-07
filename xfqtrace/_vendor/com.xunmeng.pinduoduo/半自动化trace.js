// 拼多多 (com.xunmeng.pinduoduo) trace launcher
// hook 点：libpdd_secure.so + 0xFA94
// 对应 java：SecureNative.ng2(Context,String,String,String,String,String,long,String) -> String
// 版本：8.5.0

const CONFIG = {
    package: "com.xunmeng.pinduoduo",
    target: {type: "func", so_name: "libpdd_secure.so", offset: 0xFA94},
    options: {
        inline_hook_backend: 2,
        out_format: "traceui",
        lz4_compression: { enable: true, level: 0 },
        stop_condition: { max_traces: 1 },
        anon_trace: false,
        // 静态方法：x0=env, x1=jclass, x2=Context, x3-x7=前5个String
        // s0=long(第6个参数), s1=最后一个String（栈上参数）
        hook_format: { args: "env,obj,obj,jstr,jstr,jstr,jstr,jstr,long,jstr", ret: "jstr" },
    },
};

// ======================== 以下为脚本逻辑，一般不需要修改 ========================

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

    g_done_callback = new NativeCallback(function() { send({type: "trace_done"}); }, "void", []);
    set_done_cb(g_done_callback);
}

var g_armed = false;
var g_dlopen_listener = Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {},
    onLeave: function(retval) {
        if (!g_armed && Process.findModuleByName(CONFIG.target.so_name)) {
            g_armed = true;
            g_dlopen_listener.detach();
            armTrace();
        }
    }
});

if (Process.findModuleByName(CONFIG.target.so_name)) { g_armed = true; armTrace(); }
console.log("[*] waiting for " + CONFIG.target.so_name + " ...");

rpc.exports = {
    stop: function() {
        if (!g_armed) g_dlopen_listener.detach();
        if (g_handle) {
            try { getApi("xfqtrace_stop", "void", [])(); } catch(e) {}
            try { getApi("xfqtrace_set_done_callback", "void", ["pointer"])(ptr(0)); } catch(e) {}
        }
        g_done_callback = null;
        console.log("[*] qtrace stopped");
    }
};
