# Trace Tenet - Android 逆向追踪分析工具集

一套完整的 Android 逆向工程追踪分析工具包，支持原生追踪生成和 IDA Pro 追踪可视化。

## 项目结构

```
trace_tenet/
├── trace_tools/
│   ├── libtrace.so           # 原生追踪库（推送到 /data/local/tmp/）
│   ├── trace_helper.js       # 使用 libtrace.so 的 Frida 脚本
│   └── tenet_tracer_v2.js    # 基于 Frida Stalker 的追踪器
├── tenet/                    # Tenet IDA Pro 插件
│   ├── integration/          # IDA 集成
│   ├── trace/                # 追踪文件读取与解析
│   └── ui/                   # 用户界面
└── tenet_plugin.py           # IDA 插件入口
```

## 功能特性

- **原生追踪库** (`libtrace.so`) - 使用 QBDI 实现高性能追踪
- **Frida 集成** - 两种追踪方式（libtrace.so / Stalker）
- **Tenet 格式** - 兼容 IDA Pro 的 Tenet 追踪浏览器
- **IDA Pro 插件** - 可视化执行追踪，支持内存/寄存器跟踪

---

## 第一部分：Android 端追踪生成

### 方法 A：使用 libtrace.so（推荐）

#### 1. 将 libtrace.so 推送到设备

```bash
adb push trace_tools/libtrace.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/libtrace.so
```

#### 2. 配置 trace_helper.js

编辑 `trace_tools/trace_helper.js`，修改 `CONFIG` 对象：

```javascript
var CONFIG = {
    // libtrace.so 在设备上的路径
    traceLibraryPath: "/data/local/tmp/libtrace.so",

    // 追踪模式
    // 0 = CALL_ONLY      - 仅追踪函数调用
    // 1 = FULL_TRACE     - 追踪所有指令
    // 2 = SVC_TRACE      - 追踪 SVC 指令
    // 3 = TENET_TRACE    - 生成 Tenet 兼容格式
    currentMode: 3,

    // 输出模式
    // 0 = FILE      - 仅保存到文件
    // 1 = CONSOLE   - 仅打印到 logcat
    // 2 = BOTH      - 同时输出到文件和 logcat
    outputMode: 0,

    // 目标配置
    targets: [
        {
            moduleName: "libtarget.so",      // 目标 SO 模块名
            hooks: [
                {
                    type: "offset",           // 按偏移地址 Hook
                    offset: 0x1234,          // 函数偏移
                    signature: ["pointer", "pointer"],  // 函数签名
                    replace: true,           // 替换函数
                    name: "target_function"  // 日志中的函数名
                }
            ]
        }
    ]
};
```

#### 3. 使用 trace_helper.js 运行 Frida

```bash
# 启动应用
frida -U -f com.example.app -l trace_tools/trace_helper.js --no-pause

# 或附加到运行中的进程
frida -U com.example.app -l trace_tools/trace_helper.js
```

追踪文件默认会生成在 `/data/local/tmp/` 目录下。

---

### 方法 B：使用 Frida Stalker（更简单）

`tenet_tracer_v2.js` 脚本使用 Frida 内置的 Stalker 进行追踪。它会自动检测包名并将追踪保存到应用的数据目录。

#### 1. 配置 tenet_tracer_v2.js

编辑 `trace_tools/tenet_tracer_v2.js`：

```javascript
// 目标配置
const TARGET_MODULE = "libtarget.so";      // 目标 SO 模块
const TARGET_OFFSET = 0x1234;              // 要追踪的函数偏移
const MAX_INSTRUCTIONS = 900000000;        // 指令数量限制
const PACKAGE_NAME = "com.example.app";    // 可选：null 表示自动检测
const OUTPUT_FILENAME = "tenet.trace";     // 输出文件名
```

#### 2. 运行追踪器

```bash
# 启动应用
frida -U -f com.example.app -l trace_tools/tenet_tracer_v2.js --no-pause

# 或附加到运行中的进程
frida -U com.example.app -l trace_tools/tenet_tracer_v2.js
```

#### 3. 追踪文件位置

脚本会自动将追踪文件保存到：
- 主路径：`/data/data/<包名>/tenet.trace`
- 备用路径：`/data/local/tmp/tenet.trace`

拉取追踪文件：

```bash
# 追踪完成后
adb pull /data/data/com.example.app/tenet.trace ./
```

---

## 第二部分：在 IDA Pro 中安装 Tenet 插件

### 步骤 1：找到 IDA 插件目录

**Windows:**
```
C:\Users\<用户名>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\
```

**Linux:**
```
~/.idapro/plugins/
```

**macOS:**
```
~/.idapro/plugins/
```

### 步骤 2：复制 Tenet 文件

复制整个 `tenet` 目录和插件文件：

```bash
# Windows 示例
xcopy /E /I tenet C:\Users\<用户名>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\tenet
copy tenet_plugin.py C:\Users\<用户名>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\
```

或手动操作：
1. 将 `tenet/` 文件夹复制到 IDA 的 `plugins/` 目录
2. 将 `tenet_plugin.py` 复制到 IDA 的 `plugins/` 目录

### 步骤 3：验证安装

1. 重启 IDA Pro
2. 打开任意 IDB 数据库
3. 在 `Edit -> Plugins` 菜单中检查 "Tenet"（或它会自动加载）

---

## 第三部分：在 IDA Pro 中使用 Tenet

### 加载追踪文件

1. 在 IDA Pro 中打开你的 IDB 数据库
2. 确保目标 SO 已加载到正确的基址
3. 通过菜单加载追踪：`File -> Load -> Tenet Trace`（或使用插件菜单）
4. 选择你的 `tenet.trace` 文件

### Tenet UI 功能

- **Trace View** - 单步执行追踪
- **Register View** - 查看寄存器随时间的变化
- **Memory View** - 跟踪内存读/写操作
- **Breakpoint View** - 管理执行断点
- **Hex View** - 检查内存区域

### 键盘快捷键

加载后，Tenet 提供标准的追踪控制：
- `F5` / `F9` - 开始/继续追踪回放
- `F7` - 单步进入
- `F8` - 单步跳过
- 地址跳转导航快捷键

---

## 配置示例

### 示例 1：追踪加密函数

```javascript
// trace_helper.js
targets: [
    {
        moduleName: "libencrypt.so",
        hooks: [
            {
                type: "offset",
                offset: 0x45078,
                signature: ["pointer", "pointer", "pointer", "pointer"],
                replace: true,
                name: "encrypt_function"
            }
        ]
    }
]
```

### 示例 2：多个函数

```javascript
targets: [
    {
        moduleName: "libtarget.so",
        hooks: [
            {
                type: "offset",
                offset: 0x1000,
                signature: ["int", "pointer"],
                replace: false,
                name: "func_init"
            },
            {
                type: "symbol",
                symbolName: "process_data",
                signature: ["pointer"],
                replace: true,
                name: "func_process"
            }
        ]
    }
]
```

---

## 故障排除

### libtrace.so 相关问题

**错误：`dlopen failed`**
```bash
# 检查文件权限
adb shell ls -la /data/local/tmp/libtrace.so

# 确保可执行
adb shell chmod 755 /data/local/tmp/libtrace.so

# 检查架构兼容性（arm64 vs arm）
adb shell file /data/local/tmp/libtrace.so
```

### Frida Stalker 相关问题

**追踪文件未创建：**
- 检查写权限：`adb shell ls -la /data/data/<包名>/`
- 如果自动检测失败，手动指定 `PACKAGE_NAME`
- 检查 logcat 中的错误：`adb logcat | grep -i frida`

### IDA 插件相关问题

**插件未加载：**
- 检查 IDA Python 控制台：`View -> Open subviews -> Python`
- 验证 `tenet` 文件夹结构完整
- 检查 IDA 版本兼容性（测试于 IDA Pro 7.x+）

**追踪文件无法加载：**
- 确保 SO 基址匹配（IDA 视图与追踪文件头）
- 验证追踪文件格式正确（应以 `# SO:` 开头）
- 检查追踪文件是否损坏（文件大小应合理）

---

## 架构支持

| 架构 | libtrace.so | Tenet 插件 |
|------|-------------|------------|
| ARM64   | ✓           | ✓          |
| ARM32   | ✓           | ✓          |
| x86     | -           | ✓          |
| x64     | -           | ✓          |

---

## 参考资料

- Tenet: https://github.com/gaasedelen/tenet
- Frida: https://frida.re/docs/
- QBDI: https://qbdi.quarkslab.com/

---

## 许可证

本项目基于 [Tenet](https://github.com/gaasedelen/tenet) by gaasedelen 修改。
请参考原项目获取许可信息。

---

## 贡献

这是 Tenet 的修改/定制版本，用于 Android 追踪分析。
如有问题或疑问，请参考原 Tenet 仓库。
