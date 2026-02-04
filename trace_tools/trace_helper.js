/**
 * Frida Trace Helper - libtrace.so 集成脚本
 *
 * 功能说明：
 * 1. 通过 dlopen 加载 libtrace.so
 * 2. 等待目标 SO 模块加载
 * 3. Hook 指定函数并将参数传递给 qbdi_trace_with_mode_c
 * 4. 支持抽象化的模式配置
 */

// ==================== 配置区域 ====================

var CONFIG = {
    // libtrace.so 的路径（已 push 到 /data/local/tmp/）
    traceLibraryPath: "/data/local/tmp/libtrace.so",


    // 0 CALL_ONLY,      // 仅追踪函数调用
    // 1 FULL_TRACE,     // 追踪所有指令
    // 2 SVC_TRACE,      // 追踪 svc 指令
    // 3 TENET_TRACE,    // 生成 Tenet 兼容的执行追踪格式
    // trace 模式（用户自定义）
    // 根据你的 libtrace.so 实现来定义模式值
    traceMode: {
        FULL_TRACE: 1,
        SVC_TRACE: 2,
        TENET_TRACE: 3,
        CALL_ONLY: 0
    },

    // 当前使用的模式
    currentMode:3,


       // 0 FILE,       // 仅保存到文件
       // 1 CONSOLE,    // 仅打印到控制台 (Logcat)
       // 2  BOTH        // 同时保存到文件和打印到控制台
    // 输出模式 (0=FILE, 1=CONSOLE, 2=BOTH)
    outputMode: 0,

    // 目标配置
    targets: [
        {
            // 目标 SO 模块名
            moduleName: "libcovault-appsec.so",

            // Hook 配置列表
            hooks: [
                {
                    // 使用方式 1: 绝对偏移地址
                    type: "offset",
                    offset: 0x45078,

                    // 函数签名（用于生成正确的参数处理）
                    // 支持: pointer, int, uint32, string, jstring, float, double 等
                    signature: ["pointer", "pointer","pointer","pointer"],

                    // 是否替换原函数（true=替换, false=仅监听）
                    replace: true,

                    // 自定义名称（用于日志）
                    name: "encode_function"
                },
                // 可以添加更多 hook 配置
                // {
                //     type: "symbol",
                //     symbolName: "function_name",
                //     signature: ["pointer", "int"],
                //     replace: false,
                //     name: "another_function"
                // }
            ]
        }
    ]
};

// ==================== 核心实现 ====================

/**
 * TraceSoLoader - SO 加载和管理器
 */
var TraceSoLoader = (function() {
    var handle = null;
    var traceFunction = null;

    /**
     * 加载 libtrace.so
     */
    function loadTraceLibrary(soPath) {
        try {
            console.log("[*] Loading trace library: " + soPath);

            // 获取 dlopen 函数
            var dlopenPtr = Module.findExportByName(null, 'dlopen');
            if (!dlopenPtr) {
                throw new Error("Failed to find dlopen symbol");
            }

            var dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);

            // 分配路径字符串并加载 SO
            var soPathPtr = Memory.allocUtf8String(soPath);
            handle = dlopen(soPathPtr, 2); // RTLD_NOW

            if (handle.isNull()) {
                throw new Error("dlopen failed to load " + soPath);
            }

            console.log("[+] Trace library loaded successfully, handle: " + handle);
            return handle;

        } catch (e) {
            console.log("[-] Error loading trace library: " + e.message);
            return null;
        }
    }

    /**
     * 获取 trace 函数
     * 函数签名: qbdi_trace_with_mode_c(funcPtr, args, arg_count, retVal, modeType, outputMode)
     */
    function getTraceFunction() {
        if (traceFunction) {
            return traceFunction;
        }

        try {
            console.log("[*] Finding trace function...");

            // 从 libtrace.so 中导出 qbdi_trace_with_mode_c 函数
            var traceAddr = Module.findExportByName("libtrace.so", 'qbdi_trace_with_mode_c');
            if (!traceAddr) {
                throw new Error("Failed to find qbdi_trace_with_mode_c symbol");
            }

            // 创建 NativeFunction
            // 返回类型: void
            // 参数: funcPtr(pointer), args(pointer), arg_count(uint32), retVal(pointer), modeType(int), outputMode(int)
            traceFunction = new NativeFunction(traceAddr, 'void', ['pointer', 'pointer', 'uint32', 'pointer', 'int', 'int']);

            console.log("[+] Trace function found at: " + traceAddr);
            return traceFunction;

        } catch (e) {
            console.log("[-] Error getting trace function: " + e.message);
            return null;
        }
    }

    return {
        load: function(soPath) {
            return loadTraceLibrary(soPath);
        },

        getTraceFunc: function() {
            return getTraceFunction();
        },

        getHandle: function() {
            return handle;
        }
    };
})();

/**
 * ArgumentProcessor - 参数处理器
 */
var ArgumentProcessor = {
    /**
     * 准备参数数组
     * 将各种类型的参数转换为指针数组
     */
    prepareArgs: function(args) {
        if (args === undefined || !Array.isArray(args)) {
            args = [];
        }

        var argNum = args.length;
        var argSize = Process.pointerSize * argNum;
        var argsPtr = Memory.alloc(argSize);

        for (var i = 0; i < argNum; i++) {
            var arg = args[i];
            var argPtr;

            // 处理 null/undefined
            if (arg === null || arg === undefined) {
                argPtr = ptr(0);
            }
            // 处理 NativePointer
            else if (arg instanceof NativePointer) {
                argPtr = arg;
            }
            // 处理普通对象（如 JNIEnv 等）
            else if (typeof arg === 'object' && arg.hasOwnProperty('handle')) {
                argPtr = arg.handle;
            }
            // 处理数字
            else if (typeof arg === 'number') {
                // 区分整数和浮点数
                if (Number.isInteger(arg)) {
                    argPtr = ptr(arg);
                } else {
                    // 浮点数需要特殊处理
                    var floatPtr = Memory.alloc(8);
                    Memory.writeDouble(floatPtr, arg);
                    argPtr = floatPtr;
                }
            }
            // 处理字符串
            else if (typeof arg === 'string') {
                argPtr = Memory.allocUtf8String(arg);
            }
            // 处理二进制数据
            else if (typeof arg === 'object' && arg instanceof ArrayBuffer) {
                var dataPtr = Memory.alloc(arg.byteLength);
                Memory.writeByteArray(dataPtr, new Uint8Array(arg));
                argPtr = dataPtr;
            }
            // 处理 ArrayBuffer View (Uint8Array, etc.)
            else if (typeof arg === 'object' && arg.buffer instanceof ArrayBuffer) {
                var dataPtr = Memory.alloc(arg.byteLength);
                Memory.writeByteArray(dataPtr, arg);
                argPtr = dataPtr;
            }
            else {
                console.error('Unsupported argument type at index ' + i + ':', typeof arg);
                argPtr = ptr(0);
            }

            // 将参数指针写入参数数组
            Memory.writePointer(argsPtr.add(i * Process.pointerSize), argPtr);
        }

        return {
            argsPtr: argsPtr,
            argNum: argNum
        };
    },

    /**
     * 提取函数参数
     * 根据签名从 Interceptor 获取参数
     */
    extractArgs: function(args, signature) {
        var extractedArgs = [];

        for (var i = 0; i < signature.length; i++) {
            var type = signature[i];
            var arg = args[i];

            switch (type) {
                case 'pointer':
                case 'void*':
                case 'int8':
                case 'int16':
                case 'int32':
                case 'int64':
                case 'uint8':
                case 'uint16':
                case 'uint32':
                case 'uint64':
                    extractedArgs.push(arg);
                    break;

                case 'jstring':
                    // JNI 字符串
                    extractedArgs.push(arg);
                    break;

                case 'float':
                case 'double':
                    extractedArgs.push(arg);
                    break;

                case 'string':
                    // C 字符串
                    if (arg.isNull()) {
                        extractedArgs.push("");
                    } else {
                        extractedArgs.push(arg.readCString());
                    }
                    break;

                default:
                    extractedArgs.push(arg);
                    break;
            }
        }

        return extractedArgs;
    }
};

/**
 * ModuleWatcher - 模块加载监听器
 */
var ModuleWatcher = (function() {
    var pendingCallbacks = {};  // 模块名 -> 回调列表
    var isHookInstalled = false;

    /**
     * 通知模块已加载
     */
    function notifyModuleLoaded(moduleName) {
        var callbacks = pendingCallbacks[moduleName];
        if (callbacks) {
            var module = Process.findModuleByName(moduleName);
            if (module) {
                console.log("[+] Module loaded: " + moduleName);
                delete pendingCallbacks[moduleName];
                callbacks.forEach(function(cb) {
                    try {
                        cb(module);
                    } catch (e) {
                        console.log("[-] Callback error: " + e.message);
                    }
                });
            }
        }
    }

    /**
     * 安装 dlopen hook
     */
    function installHook() {
        if (isHookInstalled) {
            return;
        }

        try {
            var dlopenAddr = Module.findExportByName(null, "android_dlopen_ext");
            if (!dlopenAddr) {
                console.log("[-] android_dlopen_ext not found, module watching disabled");
                return;
            }

            Interceptor.attach(dlopenAddr, {
                onEnter: function(args) {
                    var pathPtr = args[0];
                    if (pathPtr !== undefined && pathPtr != null) {
                        var path = ptr(pathPtr).readCString();
                        if (path) {
                            // 提取模块名
                            var moduleName = path.split('/').pop();
                            console.log("[*] dlopen: " + path);

                            // 延迟处理，确保模块加载完成
                            setTimeout(function() {
                                notifyModuleLoaded(moduleName);
                            }, 10);
                        }
                    }
                }
            });

            isHookInstalled = true;
            console.log("[+] dlopen hook installed");
        } catch (e) {
            console.log("[-] Failed to install dlopen hook: " + e.message);
        }
    }

    return {
        /**
         * 等待模块加载
         */
        waitForModule: function(moduleName, callback) {
            // 首次使用时安装 hook
            if (!isHookInstalled) {
                installHook();
            }

            // 检查模块是否已加载
            var module = Process.findModuleByName(moduleName);
            if (module) {
                console.log("[+] Module already loaded: " + moduleName);
                callback(module);
                return;
            }

            // 添加到等待列表
            console.log("[*] Waiting for module: " + moduleName);
            if (!pendingCallbacks[moduleName]) {
                pendingCallbacks[moduleName] = [];
            }
            pendingCallbacks[moduleName].push(callback);
        }
    };
})();

/**
 * HookManager - Hook 管理器
 */
var HookManager = {
    /**
     * 等待模块加载
     */
    waitForModule: function(moduleName, callback) {
        ModuleWatcher.waitForModule(moduleName, callback);
    },

    /**
     * Hook 目标函数
     */
    hookTarget: function(targetConfig, traceFunc, outputMode, mode) {
        var moduleName = targetConfig.moduleName;
        var hooks = targetConfig.hooks;

        this.waitForModule(moduleName, function(module) {
            console.log("[*] Setting up hooks for: " + moduleName);

            hooks.forEach(function(hookConfig) {
                try {
                    var targetFuncAddr;

                    // 根据 hook 类型获取地址
                    if (hookConfig.type === "offset") {
                        targetFuncAddr = module.base.add(hookConfig.offset);
                        console.log("[*] Hooking at offset: 0x" + hookConfig.offset.toString(16));
                    } else if (hookConfig.type === "symbol") {
                        targetFuncAddr = Module.findExportByName(moduleName, hookConfig.symbolName);
                        if (!targetFuncAddr) {
                            throw new Error("Symbol not found: " + hookConfig.symbolName);
                        }
                        console.log("[*] Hooking symbol: " + hookConfig.symbolName);
                    } else {
                        throw new Error("Unknown hook type: " + hookConfig.type);
                    }

                    console.log("[+] Target address: " + targetFuncAddr);

                    // 生成参数处理代码
                    var paramNames = [];
                    for (var i = 0; i < hookConfig.signature.length; i++) {
                        paramNames.push("arg" + i);
                    }
                    var paramList = paramNames.join(",");

                    // 创建 Hook 函数（使用 Function 构造器避免 eval 作用域问题）
                    var hookBody = "    console.log('[*] " + hookConfig.name + " called');\n" +
                        "    \n" +
                        "    // 提取参数\n" +
                        "    var args = [" + paramNames + "];\n" +
                        "    \n" +
                        "    // 准备 trace 参数\n" +
                        "    var {argsPtr, argNum} = ArgumentProcessor.prepareArgs(args);\n" +
                        "    var retValPtr = Memory.alloc(8);  // 分配返回值空间\n" +
                        "    \n" +
                        "    // 调用 trace 函数\n" +
                        "    console.log('[*] Calling trace with mode: ' + " + mode + " + ', outputMode: ' + " + outputMode + ");\n" +
                        "    \n" +
                        "    _traceFunc(_targetFuncAddr, argsPtr, argNum, retValPtr, " + mode + ", " + outputMode + ");\n" +
                        "    \n" +
                        "    // 读取 trace 函数填充的返回值\n" +
                        "    var retVal = retValPtr.readPointer();\n" +
                        "    console.log('[+] Trace completed, return value: ' + retVal);\n" +
                        "    \n" +
                        "    return retVal;  // 返回实际的函数返回值\n";

                    // 使用 Function 构造器创建函数
                    var hookFn = new Function('ArgumentProcessor', '_traceFunc', '_targetFuncAddr', paramList, hookBody);

                    // 绑定参数并创建 NativeCallback
                    var boundHookFn = hookFn.bind(null, ArgumentProcessor, traceFunc, targetFuncAddr);
                    var hookCallback = new NativeCallback(boundHookFn, 'pointer', hookConfig.signature);

                    if (hookConfig.replace) {
                        // 保存原函数指针用于直接调用
                        var originalFunc = new NativeFunction(targetFuncAddr, 'pointer', hookConfig.signature);

                        // 创建新的 Hook 回调，先调用原函数再 trace
                        var replaceHookFn = new Function('ArgumentProcessor', '_traceFunc', '_originalFunc', '_targetFuncAddr', '_outputMode', '_mode', paramList,
                            "    console.log('[*] " + hookConfig.name + " called');\n" +
                            "    \n" +
                            "    // 提取参数\n" +
                            "    var args = [" + paramNames + "];\n" +
                            "    \n" +
                            "    // 先调用原函数获取返回值\n" +
                            "    var retVal = _originalFunc(" + paramNames + ");\n" +
                            "    \n" +
                            "    // 准备 trace 参数\n" +
                            "    var {argsPtr, argNum} = ArgumentProcessor.prepareArgs(args);\n" +
                            "    var retValPtr = Memory.alloc(8);\n" +
                            "    Memory.writePointer(retValPtr, retVal);\n" +
                            "    \n" +
                            "    // 延迟执行 trace，避免记录当前的调用栈\n" +
                            "    setTimeout(function() {\n" +
                            "        try {\n" +
                            "            _traceFunc(_targetFuncAddr, argsPtr, argNum, retValPtr, " + mode + ", " + outputMode + ");\n" +
                            "            console.log('[+] Background trace completed');\n" +
                            "        } catch(e) {\n" +
                            "            console.log('[-] Background trace error: ' + e.message);\n" +
                            "        }\n" +
                            "    }, 0);\n" +
                            "    \n" +
                            "    console.log('[+] Function returned: ' + retVal);\n" +
                            "    return retVal;\n"
                        );

                        var boundReplaceHook = replaceHookFn.bind(null, ArgumentProcessor, traceFunc, originalFunc, targetFuncAddr, outputMode, mode);
                        var replaceCallback = new NativeCallback(boundReplaceHook, 'pointer', hookConfig.signature);

                        Interceptor.replace(targetFuncAddr, replaceCallback);
                        console.log("[+] Replaced function at: " + targetFuncAddr);
                    } else {
                        // 仅监听（不替换）
                        Interceptor.attach(targetFuncAddr, {
                            onEnter: function(args) {
                                console.log('[*] ' + hookConfig.name + ' called');

                                // 提取参数
                                var extractedArgs = ArgumentProcessor.extractArgs(args, hookConfig.signature);

                                // 准备 trace 参数
                                var {argsPtr, argNum} = ArgumentProcessor.prepareArgs(extractedArgs);
                                var retValPtr = Memory.alloc(8);  // 分配返回值空间

                                // 调用 trace 函数
                                console.log('[*] Calling trace with mode: ' + mode + ', outputMode: ' + outputMode);

                                traceFunc(targetFuncAddr, argsPtr, argNum, retValPtr, mode, outputMode);
                                console.log('[+] Trace completed');
                            }
                        });
                        console.log("[+] Attached listener to: " + targetFuncAddr);
                    }

                } catch (e) {
                    console.log("[-] Error setting up hook: " + e.message);
                    console.log(e.stack);
                }
            });
        });
    },

    /**
     * 应用所有配置
     */
    applyConfig: function(config, traceFunc) {
        console.log("[*] Applying hook configuration...");

        config.targets.forEach(function(target) {
            this.hookTarget(target, traceFunc, config.outputMode, config.currentMode);
        }.bind(this));
    }
};

// ==================== 主程序入口 ====================

/**
 * 初始化并启动 trace
 */
function main() {
    console.log("========================================");
    console.log(" Frida Trace Helper");
    console.log("========================================");

    // 1. 加载 libtrace.so
    var handle = TraceSoLoader.load(CONFIG.traceLibraryPath);
    if (!handle) {
        console.log("[-] Failed to load trace library, exiting...");
        return;
    }

    // 2. 获取 trace 函数
    var traceFunc = TraceSoLoader.getTraceFunc();
    if (!traceFunc) {
        console.log("[-] Failed to get trace function, exiting...");
        return;
    }

    // 3. 应用 hook 配置
    HookManager.applyConfig(CONFIG, traceFunc);

    console.log("========================================");
    console.log("[+] Trace helper initialized successfully");
    console.log("[*] Waiting for target functions to be called...");
    console.log("========================================");
}

// 自动启动
setTimeout(main, 100);

// ==================== 导出 API ====================

/**
 * 提供给外部使用的 API
 */
var api = {
    // 设置 trace 模式
    setTraceMode: function(mode) {
        CONFIG.currentMode = mode;
        console.log("[*] Trace mode set to: " + mode);
    },

    // 设置输出模式
    setOutputMode: function(mode) {
        CONFIG.outputMode = mode;
        console.log("[*] Output mode set to: " + mode + " (0=BOTH, 1=FILE, 2=LOGCAT)");
    },

    // 添加目标 hook
    addTarget: function(targetConfig) {
        var traceFunc = TraceSoLoader.getTraceFunc();
        if (traceFunc) {
            HookManager.hookTarget(targetConfig, traceFunc, CONFIG.outputMode, CONFIG.currentMode);
        }
    },

    // 手动调用 trace
    traceFunction: function(funcAddr, args) {
        var traceFunc = TraceSoLoader.getTraceFunc();
        if (traceFunc) {
            var {argsPtr, argNum} = ArgumentProcessor.prepareArgs(args);
            var retValPtr = Memory.alloc(8);  // 分配返回值空间
            traceFunc(funcAddr, argsPtr, argNum, retValPtr, CONFIG.currentMode, CONFIG.outputMode);
            // 读取并返回 trace 函数填充的返回值
            return retValPtr.readPointer();
        }
        return null;
    }
};

// 兼容直接运行和 require 加载两种方式
if (typeof exports !== 'undefined') {
    // 作为模块加载时导出 API
    Object.keys(api).forEach(function(key) {
        exports[key] = api[key];
    });
} else if (typeof module !== 'undefined' && module.exports) {
    // Node.js 风格
    module.exports = api;
}

// 将 API 挂载到全局，方便直接访问
if (typeof globalThis !== 'undefined') {
    globalThis.TraceHelper = api;
} else if (typeof global !== 'undefined') {
    global.TraceHelper = api;
}
