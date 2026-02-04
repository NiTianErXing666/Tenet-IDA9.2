# Tenet - 二进制执行轨迹时间旅行调试工具

Tenet 是一个 IDA Pro 插件，支持对二进制执行轨迹进行时间旅行调试。它允许你逐步前进或后退遍历已记录的程序执行过程，同时可以在任何执行时刻检查寄存器、内存和栈。

## 功能特性

- **时间旅行调试**：在执行轨迹中前后步进
- **寄存器检查**：在任何执行步骤查看所有 CPU 寄存器
- **内存检查**：在轨迹中的任何位置检查内存内容
- **栈分析**：检查栈状态和指针
- **断点支持**：设置并导航到执行、读取、写入、访问断点
- **架构支持**：ARM64、x86 和 x86-64
- **轨迹可视化**：程序执行的可视化时间线，带有事件标记

## 安装

1. 将 `tenet` 目录复制到 IDA 插件文件夹：
   - **Windows**: `C:\Program Files\IDA Pro\plugins\`
   - **macOS**: `/Applications/IDA Professional 9.2.app/Contents/MacOS/plugins/`
   - **Linux**: `~/.idapro/plugins/`

2. 重启 IDA Pro

3. 加载轨迹文件：`File → Load file → Tenet trace file...`（或使用菜单）

## 快速开始

### 加载轨迹文件

1. 在 IDA Pro 中打开一个二进制文件
2. 进入 `File → Load file → Tenet trace file...`
3. 选择一个 `.tt` (Tenet 轨迹) 文件
4. 轨迹加载完成后，所有 Tenet 窗口会自动显示

### 导航轨迹

轨迹加载完成后，你可以使用以下方式导航：

#### **键盘快捷键**

| 操作 | 快捷键 | 说明 |
|-----|--------|------|
| **单步进入** (Step Into) | `Ctrl+Shift+S` | 前进一条指令（进入函数调用） |
| **单步跳过** (Step Over) | `Ctrl+Shift+N` | 前进一条指令（跳过函数调用） |
| **单步退出** (Step Out) | `Ctrl+Shift+F` | 跳到返回点（退出当前函数） |
| **上一条指令** (Previous Insn) | `Ctrl+Shift+B` | 后退一条指令 |
| **继续** (Continue) | `Ctrl+Shift+C` | 前进到下一个启用的断点 |

#### **右键菜单**

在反汇编窗口中右键点击地址，可以访问：

- **Go to first execution** - 跳到该地址的第一次执行
- **Go to next execution** - 跳到该地址的下一次执行
- **Go to previous execution** - 跳到该地址的前一次执行
- **Go to final execution** - 跳到该地址的最后一次执行

### 断点

Tenet 支持以下类型的断点：
- **执行断点** (Execution): 当地址被执行时中断
- **读断点** (Memory Read): 当内存地址被读取时中断
- **写断点** (Memory Write): 当内存地址被写入时中断
- **访问断点** (Memory Access): 当发生任何内存访问（读或写）时中断

像往常一样在 IDA 中设置断点，然后使用 `Ctrl+Shift+C`（继续）跳到轨迹中下一个断点命中位置。

## UI 组件说明

### 轨迹视图（时间线）
顶部的轨迹可视化显示：
- **灰色条**：普通指令
- **蓝色高亮**：断点或事件
- **红色高亮**：内存写入
- **绿色高亮**：内存读取

单击时间线上的任何位置可跳到该执行时刻。

### 寄存器视图
显示当前执行时刻的所有 CPU 寄存器。显示项包括：
- 寄存器名称和值（十六进制）
- 自前一条指令以来改变的寄存器（高亮显示）

### 内存/十六进制视图
显示当前执行时刻的内存内容。可以手动导航内存地址，或使用断点追踪内存访问模式。

### 栈视图
显示当前栈状态及指针分析。

### 断点视图
管理轨迹中的所有断点。

## IDA 9.2 兼容性

此版本的 Tenet 已升级以支持 IDA Pro 9.2 和 PySide6（Qt6）。主要变化：

- 支持 PySide6（Qt6 兼容性）
- 更新的事件处理（`position()` 替代 `pos()`）
- 修复了 action 注册
- 改进了 ARM64 架构检测

## 轨迹文件格式

Tenet 使用 `.tt`（Tenet 轨迹）文件格式，包含：
- 指令执行历史
- 每一步的寄存器状态
- 内存读/写操作
- 架构特定信息

轨迹文件可以通过以下方式生成：
- **QEMU** 带 Tenet 追踪
- **DynamoRIO** 带 Tenet 插件
- **Pin** 带 Tenet Tool
- 其他自定义插桩工具

## 架构支持

Tenet 目前支持：
- **ARM64 (AArch64)** - 完全支持
- **x86-64** - 完全支持
- **x86** - 完全支持

## 快捷键配置

### 自定义快捷键

如果快捷键与 IDA 的其他功能冲突，可以自定义：

1. 进入 `Edit → Hotkeys`
2. 搜索 "tenet" 或 "Step Into (Tenet)" 等
3. 双击选项修改快捷键
4. 重启 IDA 生效

### 推荐的快捷键组合

- `F10` - Step Into（类似传统调试器）
- `F11` - Step Over（类似传统调试器）
- `Shift+F11` - Step Out（类似传统调试器）
- `Shift+F10` - Previous Instruction（后退一步）

## 常见问题

### 轨迹文件加载失败
- 确保 IDA 中加载的二进制文件与生成轨迹的二进制文件匹配
- 检查轨迹文件是否损坏
- 验证轨迹是为正确的架构生成的

### 快捷键不起作用
- 确保轨迹已加载（检查轨迹窗口）
- 进入 IDA 的 `Edit → Hotkeys` 验证快捷键没有冲突
- 尝试使用右键菜单代替

### 大型轨迹性能问题
- Tenet 在非常大的轨迹（数十亿指令）上可能较慢
- 如果可能，考虑创建较小的轨迹子集
- 使用断点和 Continue 功能跳过大型段

## 高级用法

### 使用 Continue 快速导航

1. 设置需要的断点
2. 按 `Ctrl+Shift+C` 跳到下一个断点
3. 使用 `Ctrl+Shift+B/S/N` 进行微调

### 跟踪内存访问

1. 在内存视图中右键点击地址
2. 选择 "Break on Write" 或 "Break on Access"
3. 按 `Ctrl+Shift+C` 跳到下一个访问

### 分析函数流程

1. 在函数入口点设置执行断点
2. 在函数返回地址设置另一个断点
3. 使用快捷键前后导航函数执行

## 源码文件说明

### 核心文件

- `trace/reader.py` - 轨迹阅读器核心逻辑
- `context.py` - 插件上下文和控制流
- `integration/ida_integration.py` - IDA 集成层
- `trace/analysis.py` - 地址重映射和分析

### UI 文件

- `ui/trace_view.py` - 轨迹可视化窗口
- `ui/hex_view.py` - 内存/十六进制视图
- `ui/reg_view.py` - 寄存器视图
- `ui/palette.py` - UI 颜色配置

### 其他

- `DEBUGGING_GUIDE.md` - 技术架构深度指南
- `types.py` - 类型定义和枚举

## 版本信息

- **当前版本**: 0.2.0
- **作者**: Markus Gaasedelen
- **发布日期**: 2021
- **IDA 兼容性**: 9.0, 9.2
- **Qt 框架**: Qt6 (PySide6)

## 许可证

Tenet 作为安全研究和教育目的提供。

## 致谢

- 原始 Tenet 作者：Markus Gaasedelen
- ARM64 支持贡献者
- IDA 9.2 兼容性更新

## 技术支持

遇到问题或有疑问：
- 查看 [调试指南](DEBUGGING_GUIDE.md) 了解技术细节
- 检查源代码注释，特别是 `trace/reader.py`
- 查看错误日志了解更多信息

## 快速参考

### 最常用的操作

```
加载轨迹:  File → Load file → Tenet trace file...
前进一步:  Ctrl+Shift+S 或 Ctrl+Shift+N
后退一步:  Ctrl+Shift+B
跳到断点:  Ctrl+Shift+C
查看地址:  右键点击地址 → Go to next execution
```

### 调试工作流

1. **加载** - 打开二进制，加载轨迹文件
2. **设置** - 设置相关的断点
3. **导航** - 使用快捷键前后移动
4. **检查** - 在寄存器、内存、栈视图中查看状态
5. **分析** - 根据时间序列分析程序行为

祝调试愉快！🎉
