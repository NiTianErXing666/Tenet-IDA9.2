/**
 * Tenet Trace Format Generator using Frida Stalker v2
 *
 * 改进版本：支持文件 I/O、进度日志、自动包名检测
 * 兼容 Frida 16.2.1+
 *
 * 生成兼容 Tenet trace explorer (IDA Pro 插件) 的 trace 文件
 * 格式说明: https://github.com/gaasedelen/tenet/tree/master/tracers
 *
 * 使用方法:
 *   frida -U -f <package> -l tenet_tracer_v2.js --no-pause
 *
 * 或附加到运行中的进程:
 *   frida -U <package> -l tenet_tracer_v2.js
 *
 * 配置说明:
 *   TARGET_MODULE - 目标 SO 模块名
 *   TARGET_OFFSET - 目标函数偏移
 *   PACKAGE_NAME - 应用包名（可选，null=自动检测）
 *   OUTPUT_FILENAME - 输出文件名（默认: tenet.trace）
 *
 * 包名检测:
 *   1. 优先使用配置中的 PACKAGE_NAME
 *   2. 从 Java Application 获取
 *   3. 从模块路径解析
 *   4. 从进程名推断
 *   5. 失败时使用备用路径 (/sdcard/ 或 /data/local/tmp/)
 *
 * 如果包名检测失败，可以在配置中手动指定:
 *   const PACKAGE_NAME = "com.example.app";
 */

'use strict';

// ==================== 配置区域 ====================
const TARGET_MODULE = "libcovault-appsec.so";    // 目标模块名
const TARGET_OFFSET = 0x45078;                   // 目标函数偏移
const MAX_INSTRUCTIONS =        900000000;               // 最大指令数限制
const FOLLOW_DEPTH = 1;                            // 跟踪调用深度
const OUTPUT_FILENAME = "tenet.trace";            // 输出文件名
const PACKAGE_NAME = "com.mobikwik_new";                        // 手动指定包名（null=自动检测）
// ==================================================

let instructionCount = 0;
let lineCount = 0;             // 已写入的行数计数器
let startTime = 0;             // 开始时间戳
let previousContext = null;
let currentMemoryOps = [];
let isTracing = false;
let traceFile = null;          // 文件句柄
let traceFileStream = null;    // Java FileOutputStream
let traceBuffer = [];          // 批量输出缓冲区
const BUFFER_FLUSH_SIZE = 5000; // 每 5000 行刷新一次（增大缓冲区提升性能）
let packageName = null;        // 包名（动态获取）
const PROGRESS_INTERVAL = 100000; // 每 10 万行打印进度

/**
 * 等待模块加载
 */
function waitForModule(moduleName, callback) {
    const module = Process.findModuleByName(moduleName);
    if (module) {
        console.log(`[*] Module ${moduleName} already loaded at ${module.base}`);
        return callback(module);
    }

    console.log(`[*] Waiting for module: ${moduleName}`);

    const dlopen = Module.findExportByName(null, "android_dlopen_ext") ||
                   Module.findExportByName(null, "dlopen");

    if (!dlopen) {
        throw new Error("dlopen/android_dlopen_ext not found");
    }

    Interceptor.attach(dlopen, {
        onEnter(args) {
            this.path = args[0].isNull() ? "" : Memory.readCString(args[0]);
        },
        onLeave(retval) {
            if (this.path.indexOf(moduleName) !== -1) {
                const module = Process.findModuleByName(moduleName);
                if (module) {
                    console.log(`[+] Module ${moduleName} loaded at ${module.base}`);
                    callback(module);
                }
            }
        }
    });
}


/**
 * 获取当前应用的包名
 */
function getPackageName() {
    // 方法0: 使用配置中的包名（最优先）
    if (PACKAGE_NAME) {
        console.error(`[*] Using configured package name: ${PACKAGE_NAME}`);
        return PACKAGE_NAME;
    }

    // 方法1: 从 Java 层获取包名
    try {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const currentApp = ActivityThread.currentApplication();
                if (currentApp) {
                    const pkg = currentApp.getPackageName();
                    if (pkg) {
                        packageName = pkg.toString();
                        console.error(`[*] Got package name from Application: ${packageName}`);
                    }
                }
            } catch (e) {
                // 尝试从 Context 获取
                try {
                    const context = Java.use("android.app.ActivityThread").currentApplication();
                    if (context) {
                        const pkg = context.getPackageName();
                        if (pkg) {
                            packageName = pkg.toString();
                            console.error(`[*] Got package name from Context: ${packageName}`);
                        }
                    }
                } catch (e2) {
                    // 忽略
                }
            }
        });
    } catch (e) {
        // Java 层获取失败
    }

    if (packageName) {
        return packageName;
    }

    // 方法2: 从环境变量获取
    try {
        // Android 应用通常有这个环境变量
        const dalvikVm = Java.use("java.lang.System");
        const dataDir = dalvikVm.getProperty("user.dir");
        if (dataDir && dataDir.includes("/data/data/")) {
            const match = dataDir.match(/\/data\/data\/([^\/]+)/);
            if (match && match[1] && !match[1].startsWith("~~")) {
                packageName = match[1];
                console.error(`[*] Got package name from system property: ${packageName}`);
                return packageName;
            }
        }
    } catch (e) {
        // 忽略
    }

    // 方法3: 从模块路径推断
    try {
        const mod = Process.findModuleByName(TARGET_MODULE);
        if (mod && mod.path) {
            // 尝试多种路径模式
            const patterns = [
                /\/data\/app\/~~([^\/]+)\/([^\/]+)\//,  // Android 10+ 隔离路径
                /\/data\/app\/([^\/]+)\//,              // 传统路径
                /\/data\/user\/\d+\/([^\/]+)\//          // 用户空间路径
            ];

            for (const pattern of patterns) {
                const match = mod.path.match(pattern);
                if (match) {
                    // pattern 1: match[2] 是真实包名，match[1] 是隔离ID
                    // pattern 2: match[1] 是包名
                    // pattern 3: match[1] 是包名
                    const pkg = match[2] || match[1];
                    if (pkg && !pkg.startsWith("~~")) {
                        packageName = pkg;
                        console.error(`[*] Got package name from module path: ${packageName}`);
                        return packageName;
                    }
                }
            }
        }
    } catch (e) {
        // 忽略
    }

    // 方法4: 从进程名推断
    try {
        const pid = Process.id;
        const cmdline = new File("/proc/" + pid + "/cmdline", "r");
        const processName = cmdline.readAll().replace(/\0+$/, '').trim();
        cmdline.close();

        if (processName && processName.includes('.') && !processName.startsWith("~~")) {
            packageName = processName;
            console.error(`[*] Got package name from cmdline: ${packageName}`);
            return packageName;
        }
    } catch (e) {
        // 忽略
    }

    // 方法5: 使用备用目录（/sdcard/ 或 /data/local/tmp/）
    console.error(`[!] Warning: Could not detect package name, using fallback directory`);
    return "FALLBACK_PACKAGE";
}

/**
 * 获取应用的私有目录（使用 Java API）
 */
function getAppDataDir() {
    let appDir = null;

    try {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const app = ActivityThread.currentApplication();

                if (app) {
                    // 尝试获取应用的 files 目录
                    const filesDir = app.getFilesDir();
                    if (filesDir) {
                        const path = filesDir.getAbsolutePath();
                        console.error(`[*] Got app files dir: ${path}`);
                        appDir = path.toString();
                        return;
                    }

                    // 备用：尝试获取 cache 目录
                    const cacheDir = app.getCacheDir();
                    if (cacheDir) {
                        const path = cacheDir.getAbsolutePath();
                        console.error(`[*] Got app cache dir: ${path}`);
                        appDir = path.toString();
                        return;
                    }
                }
            } catch (e) {
                console.error(`[!] Failed to get app dir: ${e}`);
            }
        });
    } catch (e) {
        console.error(`[!] Java.perform failed: ${e}`);
    }

    return appDir;
}

/**
 * 获取输出文件路径
 */
function getOutputPath() {
    // 方法1: 使用 Java API 获取应用目录
    const appDir = getAppDataDir();
    if (appDir) {
        return `${appDir}/${OUTPUT_FILENAME}`;
    }

    // 方法2: 使用包名
    if (!packageName) {
        packageName = getPackageName();
    }

    if (packageName !== "FALLBACK_PACKAGE") {
        return `/data/data/${packageName}/${OUTPUT_FILENAME}`;
    }

    // 方法3: 最后的备用路径
    const fallbackPaths = [
        `/data/local/tmp/${OUTPUT_FILENAME}`,
        `/sdcard/Android/${OUTPUT_FILENAME}`,
        `/storage/emulated/0/${OUTPUT_FILENAME}`,
        `/sdcard/${OUTPUT_FILENAME}`
    ];

    return fallbackPaths[0];
}

/**
 * 打开 trace 文件（使用 Frida File API，类似 dump_so）
 */
function openTraceFile() {
    // 获取包名（如果没有的话）
    if (!packageName) {
        packageName = getPackageName();
    }

    // 构造文件路径（参考 dump_so 的方式）
    let targetPath = null;

    // 方法1: 使用包名路径（类似 dump_so）
    if (packageName && packageName !== "FALLBACK_PACKAGE") {
        targetPath = `/data/data/${packageName}/${OUTPUT_FILENAME}`;
        console.error(`[*] Target path: ${targetPath}`);
    }

    // 方法2: 尝试备用路径
    if (!targetPath) {
        const fallbackPaths = [
            `/data/local/tmp/${OUTPUT_FILENAME}`,
            `/sdcard/Android/${OUTPUT_FILENAME}`
        ];
        targetPath = fallbackPaths[0];
        console.error(`[*] Using fallback path: ${targetPath}`);
    }

    try {
        // 直接使用 Frida File API（类似 dump_so）
        const file = new File(targetPath, "w");
        console.error(`[+] Trace file opened successfully: ${targetPath}`);

        return {
            path: targetPath,
            handle: file,
            write: function(data) {
                this.handle.write(data);
            },
            flush: function() {
                this.handle.flush();
            },
            close: function() {
                this.handle.flush();
                this.handle.close();
            }
        };
    } catch (e) {
        console.error(`[!] Failed to open trace file: ${e.message}`);
        return null;
    }
}

/**
 * 关闭 trace 文件
 */
function closeTraceFile(file) {
    if (file) {
        // 先刷新剩余缓冲区
        flushTraceBuffer();

        file.flush();
        file.close();
        console.error(`[+] Trace file closed`);
    }
}

/**
 * 格式化寄存器值为十六进制字符串
 */
function formatHex(value) {
    return "0x" + value.toString(16);
}

/**
 * 读取内存并格式化为十六进制字符串
 */
function readMemoryHex(address, size) {
    try {
        const bytes = Memory.readByteArray(address, size);
        if (!bytes) return null;

        let hex = "";
        const array = new Uint8Array(bytes);
        for (let i = 0; i < array.length; i++) {
            hex += array[i].toString(16).padStart(2, '0');
        }
        return hex;
    } catch (e) {
        return null;
    }
}

/**
 * 比较寄存器并返回变化（优化版：只比较常用寄存器）
 */
function diffRegisters(current, previous) {
    const changes = [];

    if (!previous) {
        // 首次，只输出常用寄存器
        const regs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                     'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
                     'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
                     'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'sp'];
        for (const reg of regs) {
            if (current[reg] !== undefined) {
                changes.push(`${reg}=${formatHex(current[reg])}`);
            }
        }
        changes.push(`pc=${formatHex(current.pc)}`);
        return changes;
    }

    // 只比较可能变化的寄存器（x0-x29 + sp）
    for (let i = 0; i <= 29; i++) {
        const reg = 'x' + i;
        if (current[reg] !== undefined && previous[reg] !== undefined) {
            if (current[reg].toString() !== previous[reg].toString()) {
                changes.push(`${reg}=${formatHex(current[reg])}`);
            }
        }
    }

    if (current.sp && previous.sp && current.sp.toString() !== previous.sp.toString()) {
        changes.push(`sp=${formatHex(current.sp)}`);
    }

    // PC 总是输出
    changes.push(`pc=${formatHex(current.pc)}`);

    return changes;
}

/**
 * 保存上下文快照
 */
function saveContext(context) {
    const saved = { pc: context.pc };

    if (context.sp !== undefined) saved.sp = context.sp;

    for (let i = 0; i <= 29; i++) {
        saved['x' + i] = context['x' + i] || ptr(0);
    }

    return saved;
}

/**
 * 生成 Tenet 格式行
 */
function generateTenetLine(regChanges, memoryOps) {
    const parts = regChanges;

    if (memoryOps && memoryOps.length > 0) {
        for (const op of memoryOps) {
            parts.push(op);
        }
    }

    return parts.join(',');
}

/**
 * 写入 trace 行（批量缓存到文件）
 */
function writeTraceLine(regChanges, memoryOps) {
    if (!isTracing || !traceFile) return;

    const line = generateTenetLine(regChanges, memoryOps);
    traceBuffer.push(line);

    // 批量刷新
    if (traceBuffer.length >= BUFFER_FLUSH_SIZE) {
        flushTraceBuffer();
    }

    // 每 10 万行打印进度
    lineCount++;
    if (lineCount % PROGRESS_INTERVAL === 0) {
        const linesPerSec = lineCount / ((Date.now() - startTime) / 1000);
        console.error(`[PROGRESS] Lines written: ${lineCount.toLocaleString()} (${linesPerSec.toFixed(0)} lines/sec)`);
    }
}

/**
 * 刷新缓冲区到文件
 */
function flushTraceBuffer() {
    if (traceBuffer.length === 0 || !traceFile) return;

    const output = traceBuffer.join('\n') + '\n';
    traceFile.write(output);
    traceBuffer = [];
}

/**
 * 检查指令是否有内存操作并读取内存内容
 */
function traceMemoryAccess(insn, context) {
    const ops = [];

    try {
        // ARM64 内存访问指令模式
        const memMnemonicPatterns = [
            'ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldur', 'ldurb', 'ldursw',  // 加载
            'str', 'strb', 'strh', 'stur', 'sturb',  // 存储
            'ldp', 'stp', 'ldpsw',  // 成对加载/存储
            'ldxr', 'ldaxr', 'stxr', 'stlxr',  // 独占访问
            'ldnp', 'stnp'  // 非时序加载/存储
        ];

        const mnemonic = insn.mnemonic;
        const isMemAccess = memMnemonicPatterns.some(p => mnemonic.toLowerCase().startsWith(p.substr(0, 3)));

        if (isMemAccess && insn.operands && insn.operands.length > 0) {
            // 查找内存操作数
            for (const op of insn.operands) {
                if (op && op.value && typeof op.value === 'object') {
                    const memRef = op.value;

                    // 尝试获取内存地址
                    let addr = null;
                    let size = 0;

                    // 从寄存器获取基址
                    if (memRef.base && context[memRef.base]) {
                        addr = ptr(context[memRef.base]);
                        if (memRef.disp) {
                            addr = addr.add(ptr(memRef.disp));
                        }
                    }

                    // 确定访问大小
                    const mnemonicLower = mnemonic.toLowerCase();
                    if (mnemonicLower.includes('b') || mnemonicLower.includes('urb')) {
                        size = 1;
                    } else if (mnemonicLower.includes('h') || mnemonicLower.includes('urh')) {
                        size = 2;
                    } else if (mnemonicLower.includes('p') || mnemonicLower.match(/\d/)) {
                        // 成对指令通常是 16 字节
                        size = 16;
                    } else {
                        size = 8;  // 默认 64 位
                    }

                    if (addr && size > 0) {
                        // 读取内存内容
                        try {
                            const bytes = Memory.readByteArray(addr, size);
                            if (bytes) {
                                let hex = "";
                                const array = new Uint8Array(bytes);
                                for (let i = 0; i < array.length; i++) {
                                    // 每个字节转为2位十六进制，不足补0
                                    // 例如: 15 -> "0f", 5 -> "05"
                                    hex += array[i].toString(16).padStart(2, '0');
                                }

                                // 确保十六进制字符串长度为偶数（每个字节2位字符）
                                // 例如: 4字节 = 8位十六进制字符

                                // 确定是读还是写
                                const isLoad = mnemonicLower.startsWith('ld') || mnemonicLower.startsWith('ld');
                                const accessType = isLoad ? 'mr' : 'mw';

                                ops.push(`${accessType}=${formatHex(addr)}:${hex}`);
                            }
                        } catch (e) {
                            // 内存读取失败（可能地址无效），跳过
                        }
                    }
                }
            }
        }
    } catch (e) {
        // 忽略错误
    }

    return ops;
}

/**
 * 开始 Stalker 跟踪（优化版）
 */
function startStalkerTrace(threadId, targetModule, targetEndAddress) {
    console.log(`[+] Starting Stalker trace for thread ${threadId}`);
    isTracing = true;

    Stalker.follow(threadId, {
        transform(iterator) {
            const MAX_BLOCK_SIZE = 1000;  // 增大 block size 减少编译
            let count = 0;

            let insn;
            while ((insn = iterator.next()) !== null && count < MAX_BLOCK_SIZE) {
                // 只跟踪目标模块内的指令
                const m = Process.findModuleByAddress(insn.address);
                if (!m || m.name !== targetModule.name) {
                    iterator.keep();
                    continue;
                }

                // 在每条指令前插入回调
                iterator.putCallout((context) => {
                    if (!isTracing || instructionCount >= MAX_INSTRUCTIONS) return;

                    instructionCount++;

                    // 解析指令并检测内存访问
                    let memOps = [];
                    try {
                        const currentInsn = Instruction.parse(context.pc);
                        memOps = traceMemoryAccess(currentInsn, context);
                    } catch (e) {
                        // 指令解析失败，忽略
                    }

                    // 获取寄存器变化
                    const currentCtx = saveContext(context);
                    const regChanges = diffRegisters(currentCtx, previousContext);

                    // 写入 trace 行
                    writeTraceLine(regChanges, memOps);

                    // 更新上下文
                    previousContext = currentCtx;
                });

                iterator.keep();
                count++;
            }
        }
    });
}

/**
 * 主逻辑
 */
function main() {
    console.log("===========================================");
    console.log("Tenet Trace Generator v2 (Frida Stalker)");
    console.log("===========================================");
    console.log(`Target: ${TARGET_MODULE} + 0x${TARGET_OFFSET.toString(16)}`);
    console.log(`Max Instructions: ${MAX_INSTRUCTIONS}`);
    console.log("===========================================\n");

    waitForModule(TARGET_MODULE, (module) => {
        const targetAddress = module.base.add(TARGET_OFFSET);

        console.log(`[+] Module base: ${module.base}`);
        console.log(`[+] Target function: ${targetAddress}`);
        console.log(`[*] Installing hook...\n`);

        // 跟踪递归调用
        const callDepthMap = new Map();

        Interceptor.attach(targetAddress, {
            onEnter(args) {
                const tid = Process.getCurrentThreadId();
                const depth = (callDepthMap.get(tid) || 0) + 1;
                callDepthMap.set(tid, depth);

                // 只在最外层启动 trace
                if (depth === 1) {
                    console.error(`\n[================= ENTRY ================]`);
                    console.error(`[+] Function entered at ${this.context.pc}`);
                    console.error(`[+] Thread: ${tid}`);
                    console.error(`[+] x0=${this.context.x0} x1=${this.context.x1} x2=${this.context.x2} x3=${this.context.x3}`);
                    console.error(`[=========================================]\n`);

                    // 初始化
                    instructionCount = 0;
                    lineCount = 0;
                    startTime = Date.now();
                    currentMemoryOps = [];
                    previousContext = null;
                    isTracing = true;
                    traceBuffer = [];  // 清空缓冲区

                    console.error(`[*] Tracing started at ${new Date(startTime).toISOString()}`);

                    // 打开 trace 文件（使用 Frida File API）
                    traceFile = openTraceFile();

                    if (traceFile) {
                        // 写入文件头
                        traceFile.write(`# SO: ${module.name} @ ${module.base}\n`);
                        traceFile.write(`; Tenet Trace - ${new Date().toISOString()}\n`);
                        traceFile.write(`; Function: +0x${TARGET_OFFSET.toString(16)}\n`);

                        // 记录初始状态
                        const initialCtx = saveContext(this.context);
                        const initialRegs = diffRegisters(initialCtx, null);
                        traceFile.write(generateTenetLine(initialRegs, []) + "\n");

                        previousContext = initialCtx;

                        // 启动 Stalker
                        startStalkerTrace(tid, module, null);
                    } else {
                        console.error(`[!] Failed to open trace file, aborting trace`);
                        isTracing = false;
                    }
                }
            },

            onLeave(retval) {
                const tid = Process.getCurrentThreadId();
                const depth = (callDepthMap.get(tid) || 1) - 1;

                if (depth <= 0) {
                    callDepthMap.delete(tid);
                } else {
                    callDepthMap.set(tid, depth);
                }

                // 最外层返回时停止
                if (depth === 0) {
                    isTracing = false;

                    // 计算统计信息
                    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(2);
                    const linesPerSec = (lineCount / parseFloat(elapsedTime)).toFixed(0);

                    // 保存文件路径
                    const outputPath = traceFile ? traceFile.path : "unknown";

                    // 刷新剩余缓冲区并关闭文件
                    if (traceFile) {
                        // 写入结束标记
                        traceFile.write(`; End of trace - ${instructionCount} instructions, ${lineCount} lines\n`);
                        closeTraceFile(traceFile);
                        traceFile = null;
                    }

                    console.error(`\n[================= EXIT ================]`);
                    console.error(`[+] Function returned`);
                    console.error(`[+] Total instructions traced: ${instructionCount}`);
                    console.error(`[+] Total lines written: ${lineCount.toLocaleString()}`);
                    console.error(`[+] Elapsed time: ${elapsedTime}s`);
                    console.error(`[+] Average speed: ${linesPerSec} lines/sec`);
                    console.error(`[+] Return value: ${retval}`);
                    console.error(`[========================================]\n`);

                    try {
                        Stalker.unfollow(tid);
                    } catch (e) {}

                    // 显示输出路径
                    console.error(`[+] Trace saved to: ${outputPath}`);
                    console.error(`[*] Pull file: adb pull ${outputPath} ./`);
                    console.error(`[*] Use Tenet IDA plugin to load: File -> Load -> Tenet Trace`);
                }
            }
        });

        console.log(`[+] Hook installed!`);
        console.log(`[*] Trigger the target function to begin tracing...\n`);
    });
}

// 启动
setImmediate(main);
