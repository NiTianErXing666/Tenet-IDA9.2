# Frida Trace Helper 使用指南

## 📋 目录

1. [功能介绍](#功能介绍)
2. [快速开始](#快速开始)
3. [配置说明](#配置说明)
4. [使用方法](#使用方法)
5. [API 参考](#api-参考)
6. [常见问题](#常见问题)
7. [参考资料](#参考资料)

---

## 功能介绍

Frida Trace Helper 是一个将 `libtrace.so` 与 Frida 结合使用的工具脚本，主要功能包括：

- ✅ 通过 `dlopen` 动态加载 `libtrace.so`
- ✅ 等待并自动检测目标 SO 模块加载
- ✅ Hook 指定函数并传递参数给 `qbdi_trace_with_mode_c`
- ✅ 抽象化的模式配置系统
- ✅ 支持多种参数类型自动转换
- ✅ 灵活的 Hook 配置（偏移地址/符号名）

---

## 快速开始

### 1. 准备工作

```bash
# 1. 将 libtrace.so push 到设备
adb push libtrace.so /data/local/tmp/

# 2. 确保权限正确
adb shell chmod 644 /data/local/tmp/libtrace.so
```

### 2. 基础使用

编辑 `trace_helper.js` 中的配置：

```javascript
var CONFIG = {
    traceLibraryPath: "/data/local/tmp/libtrace.so",
    traceOutputPath: "/data/local/tmp/trace_output.txt",
    currentMode: 1,

    targets: [
        {
            moduleName: "libTarget.so",  // 修改为目标 SO
            hooks: [
                {
                    type: "offset",
                    offset: 0x1234,       // 修改为偏移地址
                    signature: ["pointer", "int"],
                    replace: true,
                    name: "my_function"
                }
            ]
        }
    ]
};
```

### 3. 运行脚本

```bash
# Spawn 模式（推荐）
frida -U -f com.example.app -l trace_helper.js --no-pause

# Attach 模式
frida -U com.example.app -l trace_helper.js
```

---

## 配置说明

### 核心配置项

```javascript
var CONFIG = {
    // libtrace.so 路径
    traceLibraryPath: "/data/local/tmp/libtrace.so",

    // trace 输出文件路径
    traceOutputPath: "/data/local/tmp/trace_output.txt",

    // Trace 模式定义（根据你的 libtrace.so 实现）
    traceMode: {
        MODE_BASIC: 1,           // 基础追踪
        MODE_VERBOSE: 2,         // 详细追踪
        MODE_WITH_CONTEXT: 3,    // 带上下文追踪
        MODE_FULL: 4             // 完整追踪
    },

    // 当前使用的模式
    currentMode: 1,

    // 目标配置列表
    targets: [
        {
            moduleName: "libTarget.so",
            hooks: [ /* hooks */ ]
        }
    ]
};
```

### Hook 配置项

每个 hook 支持以下配置：

| 字段 | 类型 | 说明 |
|------|------|------|
| `type` | string | Hook 类型: `"offset"` 或 `"symbol"` |
| `offset` | number | 偏移地址（当 type="offset" 时） |
| `symbolName` | string | 符号名（当 type="symbol" 时） |
| `signature` | array | 函数签名，如 `["pointer", "int"]` |
| `replace` | boolean | 是否替换原函数（true=替换, false=仅监听） |
| `name` | string | 自定义名称（用于日志） |

---

## 使用方法

### 方法 1: 修改配置文件直接运行

编辑 `trace_helper.js` 中的 `CONFIG` 对象，然后运行：

```bash
frida -U -f com.example.app -l trace_helper.js --no-pause
```

### 方法 2: 运行时动态添加 Hook

```javascript
// 在 Frida REPL 中
Java.perform(function() {
    var traceHelper = require('./trace_helper.js');

    traceHelper.addTarget({
        moduleName: "libTarget.so",
        hooks: [{
            type: "offset",
            offset: 0x1234,
            signature: ["pointer", "int"],
            replace: true,
            name: "dynamic_hook"
        }]
    });
});
```

### 方法 3: 结合 Java Hook

```javascript
// 创建 custom_hook.js
Java.perform(function() {
    // Hook Java 方法
    var MyClass = Java.use("com.example.MyClass");
    MyClass.nativeMethod.implementation = function(str) {
        console.log("[JAVA] nativeMethod called with: " + str);
        return this.nativeMethod(str);
    };

    console.log("[+] Java hook installed");
    console.log("[*] Native hooks will trace the underlying native calls");
});

// 加载 trace_helper
// frida -U -f com.example.app -l custom_hook.js -l trace_helper.js --no-pause
```

### 方法 4: 手动调用 Trace

```javascript
var traceHelper = require('./trace_helper.js');

var module = Process.findModuleByName("libTarget.so");
var funcAddr = module.base.add(0x1234);

var args = [ptr(0x1234), 100, "test"];
var result = traceHelper.traceFunction(funcAddr, args);
```

---

## API 参考

### 导出函数

#### `setTraceMode(mode)`

设置 trace 模式。

```javascript
traceHelper.setTraceMode(2);  // 切换到详细模式
```

#### `addTarget(targetConfig)`

动态添加目标 hook。

```javascript
traceHelper.addTarget({
    moduleName: "libTarget.so",
    hooks: [{ ... }]
});
```

#### `traceFunction(funcAddr, args)`

手动调用 trace 函数。

```javascript
var result = traceHelper.traceFunction(funcPtr, [arg1, arg2, arg3]);
```

### 支持的参数类型

| 签名类型 | 说明 | 示例 |
|----------|------|------|
| `pointer` | 通用指针 | `void*`, `char*` |
| `int8` | 8位整数 | `int8_t` |
| `int16` | 16位整数 | `int16_t` |
| `int32` | 32位整数 | `int32_t`, `int` |
| `int64` | 64位整数 | `int64_t`, `long long` |
| `uint8` | 8位无符号整数 | `uint8_t` |
| `uint16` | 16位无符号整数 | `uint16_t` |
| `uint32` | 32位无符号整数 | `uint32_t` |
| `uint64` | 64位无符号整数 | `uint64_t` |
| `jstring` | JNI 字符串 | `jstring` |
| `string` | C 字符串 | `char*` |
| `float` | 单精度浮点数 | `float` |
| `double` | 双精度浮点数 | `double` |

### 参数自动转换

脚本会自动转换以下类型：

- ✅ NativePointer → 直接使用
- ✅ 数字 → ptr(number)
- ✅ 字符串 → Memory.allocUtf8String()
- ✅ 带有 handle 属性的对象 → obj.handle
- ✅ ArrayBuffer/TypedArray → Memory.alloc()

---

## 常见问题

### Q1: 如何找到目标函数的偏移地址？

```bash
# 使用 objdump
objdump -d libTarget.so | grep "目标函数"

# 或使用 Frida
frida -U -f com.example.app -e 'console.log(Module.findBaseAddress("libTarget.so"))'
```

### Q2: Hook 后原函数还会执行吗？

取决于 `replace` 配置：
- `replace: true` - 原函数不会执行（被替换）
- `replace: false` - 原函数正常执行（仅监听）

### Q3: 如何调试 Hook 是否成功？

查看 Frida 控制台输出：
```
[*] Loading trace library: /data/local/tmp/libtrace.so
[+] Trace library loaded successfully
[*] Finding trace function...
[+] Trace function found at: 0x...
[*] Waiting for module: libTarget.so
[+] Module loaded: libTarget.so
[+] Target address: 0x...
[+] Replaced function at: 0x...
```

### Q4: 支持多个模块吗？

支持，在 `targets` 数组中添加多个模块配置：

```javascript
targets: [
    {
        moduleName: "libModule1.so",
        hooks: [{ ... }]
    },
    {
        moduleName: "libModule2.so",
        hooks: [{ ... }]
    }
]
```

### Q5: 如何修改 trace 模式？

有两种方式：

1. 修改配置文件中的 `currentMode`
2. 运行时调用 `traceHelper.setTraceMode(mode)`

### Q6: 参数类型不匹配怎么办？

检查 `signature` 配置是否正确。常见问题：
- JNI 函数需要包含 `JNIEnv*` 和 `jobject` 参数
- 结构体指针使用 `pointer` 类型
- 字符串根据类型选择 `string` 或 `jstring`

---

## 参考资料

### 相关文件

- `trace_helper.js` - 主脚本文件
- `demo.js` - 原始示例（参考实现）
- `example_usage.js` - 使用示例集合

### 相关技术

- Frida 官方文档: https://frida.re/docs/
- dlopen 使用: http://www.yxfzedu.com/article/13102
- Android SO 注入: https://bbs.kanxue.com/thread-263072.htm

### 原理说明

1. **dlopen 加载**: 使用 `dlopen` 在运行时动态加载 `libtrace.so`
2. **符号解析**: 通过 `Module.findExportByName` 获取 trace 函数地址
3. **参数转换**: 将各种类型的参数转换为指针数组
4. **函数调用**: 调用 `qbdi_trace_with_mode_c` 进行 trace

---

## 技术支持

如有问题，请检查：

1. ✅ `libtrace.so` 是否正确 push 到 `/data/local/tmp/`
2. ✅ 路径和权限是否正确
3. ✅ 目标模块名和偏移地址是否正确
4. ✅ 函数签名是否匹配
5. ✅ 查看 Frida 控制台输出

---

**版本**: 1.0.0
**最后更新**: 2026-02-04
