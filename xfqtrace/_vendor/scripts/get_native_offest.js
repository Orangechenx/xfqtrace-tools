var is_jni_hooked =false;
function findJNIfunc_byClassName(targetClassName) {
    let symbols_libart = Module.enumerateSymbolsSync("libart.so");
    var address_RegisterNatives;
    for (const symbol of symbols_libart) {
        if (symbol.name.includes("art")
            && symbol.name.includes("JNI")
            && symbol.name.includes("RegisterNatives")
            && !symbol.name.includes("CheckJNI")
        ) {
            address_RegisterNatives = symbol.address;
            console.warn(`[*] found RegisterNative! ${address_RegisterNatives}, ${symbol.name}`);
            break;
        }
    }
    if (!address_RegisterNatives) {
        console.error(`[x] not found RegisterNative!`);
        return;
    }
    let foundMethods = []; 
    Interceptor.attach(address_RegisterNatives, {
        onEnter: function (args) {
            let env = Java.vm.tryGetEnv(); 
            let clazz_name = env.getClassName(args[1]); 
            let methods = ptr(args[2]); 
            let nMethods = args[3].toInt32(); 
            for (let i = 0; i < nMethods; i++) {
                let baseAddress_method = methods.add(i * Process.pointerSize * 3);
                let name = Memory.readCString(baseAddress_method.readPointer());
                let signature = Memory.readCString(baseAddress_method.add(Process.pointerSize).readPointer());
                let fnPtr = baseAddress_method.add(Process.pointerSize * 2).readPointer();
                if (!targetClassName || targetClassName === clazz_name) {
                    var module = Process.findModuleByAddress(fnPtr); 
                    const offset_method = fnPtr.sub(module.base); 
                    console.log(JSON.stringify({
                        "class_name": clazz_name,
                        "name&signature": `${name}${signature}`,
                        "which_so": module.name,
                        "func_offest": offset_method
                    }, null, 2))
                }
            }
        },
        onLeave: function (retval) { }
    });
    return foundMethods;
}
findJNIfunc_byClassName("com.appsflyer.internal.AFb1nSDK");

function findJNIfunc_byRegisterNatives(targetClassName) {
    if (is_jni_hooked) return;
    is_jni_hooked = true;

    let symbols_libart = Module.enumerateSymbolsSync("libart.so");
    var address_RegisterNatives;
    for (const symbol of symbols_libart) {
        if (symbol.name.includes("art") && symbol.name.includes("JNI") && symbol.name.includes("RegisterNatives") && !symbol.name.includes("CheckJNI")) {
            address_RegisterNatives = symbol.address;
            break;
        }
    }
    if (!address_RegisterNatives) return;

    console.warn(`[*] JNI 注册监控已启动...`);
    Interceptor.attach(address_RegisterNatives, {
        onEnter: function (args) {
            let env = Java.vm.getEnv();
            let clazz_name = env.getClassName(args[1]);

            // 如果不在关注列表，且没有指定全局类，则跳过
            if (targetClassName && targetClassName !== clazz_name) return;

            let methods = ptr(args[2]);
            let nMethods = args[3].toInt32();
            for (let i = 0; i < nMethods; i++) {
                let baseAddress_method = methods.add(i * Process.pointerSize * 3);
                let name = Memory.readCString(baseAddress_method.readPointer());
                let signature = Memory.readCString(baseAddress_method.add(Process.pointerSize).readPointer());
                let fnPtr = baseAddress_method.add(Process.pointerSize * 2).readPointer();

                // 打印信息
                printNativeMethodInfo("RegisterNatives (Watched)", clazz_name, name, signature, fnPtr);
            }
        }
    });
}
/**
 * 综合定位 Native 方法在 SO 中的偏移
 */
function printNativeMethodInfo(source, clazz, name, sig, fnPtr) {
    var module = Process.findModuleByAddress(fnPtr);
    if (module) {
        console.log(JSON.stringify({
            "source": source,
            "class_name": clazz,
            "name_signature": `${name}${sig}`,
            "so_name": module.name,
            "so_base": module.base,
            "func_ptr": fnPtr,
            "offset": fnPtr.sub(module.base)
        }, null, 2));
    } else {
        console.warn(`[!] [${source}] Address ${fnPtr} does not belong to any module (Method: ${clazz}.${name})`);
    }
}


function findJNIfunc_byArtMethod(className, methodName, signature) {
    Java.perform(function () {
        var clazz = Java.use(className);
        var method = signature ? clazz[methodName].overload.apply(clazz[methodName], signature.split(',')) : clazz[methodName];
        var artMethod = getArtMethod(method);

        if (artMethod) {
            var jni_offset = 16;
            var fnPtr = ptr(artMethod).add(jni_offset).readPointer();
            var mod = Process.findModuleByAddress(fnPtr);

            if (mod && mod.name.indexOf("libart.so") !== -1) {
                // 如果是 libart 的 stub，说明未完成绑定，开启 RegisterNatives 监控
                console.warn(`[!] ${className}.${methodName} 尚未绑定：已自动开启 RegisterNatives 监控，请在 App 中触发调用。`);
                findJNIfunc_byRegisterNatives(className);
            } else {
                printNativeMethodInfo("ArtMethod", className, methodName, signature, fnPtr);
            }
        }
    });
}

function getArtMethod(methodObj) {
    try {
        // 如果是 Frida 的方法包装对象，可能有 overloads
        if (methodObj.overloads) {
            methodObj = methodObj.overloads[0];
        }
        // 直接读取属性，不再使用 hasOwnProperty 防止原型链导致判断失败
        var artmethod = methodObj.$handle || methodObj.$h || methodObj.handle || null;
        return artmethod;
    } catch (e) {
        return null;
    }
}
//findJNIfunc_byArtMethod("com.appsflyer.internal.AFb1nSDK", "afRDLog", null);