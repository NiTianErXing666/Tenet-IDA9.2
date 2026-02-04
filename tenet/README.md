# Tenet - Trace Execution Navigation with Time Travel

Tenet is an IDA Pro plugin that enables time-travel debugging for binary execution traces. It allows you to navigate through recorded program execution step-by-step, both forward and backward, while inspecting registers, memory, and stack at any point in time.

## Features

- **Time-Travel Debugging**: Step forward and backward through execution traces
- **Register Inspection**: View all CPU registers at any execution step
- **Memory Inspection**: Examine memory contents at any point in the trace
- **Stack Analysis**: Inspect stack state and pointers
- **Breakpoint Support**: Set and navigate to execution, read, write, and access breakpoints
- **Architecture Support**: ARM64, x86, and x86-64
- **Trace Visualization**: Visual timeline of program execution with event markers

## Installation

1. Copy the `tenet` directory to your IDA plugins folder:
   - **Windows**: `C:\Program Files\IDA Pro\plugins\`
   - **macOS**: `/Applications/IDA Professional 9.2.app/Contents/MacOS/plugins/`
   - **Linux**: `~/.idapro/plugins/`

2. Restart IDA Pro

3. Load a trace file: `File → Load file → Tenet trace file...` (or use the menu)

## Quick Start

### Loading a Trace

1. Open a binary in IDA Pro
2. Go to `File → Load file → Tenet trace file...`
3. Select a `.tt` (Tenet trace) file
4. The trace will load and the UI will display all Tenet windows

### Navigating the Trace

Once a trace is loaded, you can navigate through execution using:

#### **Keyboard Shortcuts**

| Action | Shortcut | Description |
|--------|----------|-------------|
| **Step Into** | `Ctrl+Shift+S` | Move forward one instruction (follow function calls) |
| **Step Over** | `Ctrl+Shift+N` | Move forward one instruction (skip over function calls) |
| **Step Out** | `Ctrl+Shift+F` | Jump to return point (exit current function) |
| **Previous Instruction** | `Ctrl+Shift+B` | Move backward one instruction |
| **Continue** | `Ctrl+Shift+C` | Run forward to next enabled breakpoint |

#### **Context Menu (Right-Click)**

Right-click on an address in the disassembly view to access:

- **Go to first execution** - Navigate to the first time this address was executed
- **Go to next execution** - Navigate to the next execution of this address
- **Go to previous execution** - Navigate to the previous execution of this address
- **Go to final execution** - Navigate to the last execution of this address
- **Go to first execution (breakpoint actions)** - Search for memory access patterns

### Breakpoints

Tenet supports setting breakpoints on:
- **Execution**: Break when an address is executed
- **Memory Read**: Break when a memory address is read
- **Memory Write**: Break when a memory address is written
- **Memory Access**: Break on any memory access (read or write)

Set breakpoints in IDA as usual, then use `Ctrl+Shift+C` (Continue) to jump to the next breakpoint hit in the trace.

## UI Components

### Trace View (Timeline)
The trace visualization at the top shows:
- **Gray bars**: Normal instructions
- **Blue highlights**: Breakpoints or events
- **Red highlights**: Memory writes
- **Green highlights**: Memory reads

Click on any part of the timeline to jump to that execution point.

### Register View
Displays all CPU registers at the current execution point. Shows:
- Register names and values (in hex)
- Registers that changed since the previous instruction (highlighted)

### Memory/Hex View
Shows memory contents at the current execution point. Navigate memory addresses manually or use breakpoints to track memory access patterns.

### Stack View
Displays the current stack state with pointer analysis.

### Breakpoint View
Manages all breakpoints in the trace.

## IDA 9.2 Compatibility

This version of Tenet has been updated to support IDA Pro 9.2 and PySide6 (Qt6). Key changes:

- PySide6 support (Qt6 compatibility)
- Updated event handling (`position()` instead of `pos()`)
- Fixed action registration
- Improved architecture detection for ARM64

## Trace File Format

Tenet uses the `.tt` (Tenet Trace) file format which contains:
- Instruction execution history
- Register state at each step
- Memory read/write operations
- Architecture-specific information

Trace files can be generated from:
- **QEMU** with Tenet tracing
- **DynamoRIO** with Tenet instrumentation
- **Pin** with Tenet tool
- Other custom instrumentation tools

## Architecture Support

Tenet currently supports:
- **ARM64 (AArch64)** - Full support
- **x86-64** - Full support
- **x86** - Full support

## Troubleshooting

### Trace file fails to load
- Ensure the binary loaded in IDA matches the binary used to generate the trace
- Check that the trace file is not corrupted
- Verify the trace was generated for the correct architecture

### Shortcut keys not working
- Ensure a trace is loaded (check the trace window)
- Go to `Edit → Hotkeys` in IDA to verify the shortcuts are not conflicting
- Try using the context menu instead

### Performance issues with large traces
- Tenet may be slow with very large traces (billions of instructions)
- Consider creating a smaller trace subset if possible
- Use breakpoints and Continue to skip large sections

## Development

For development mode testing, set the environment variable:
```bash
TENET_DEV_MODE=1
```

This will automatically load a test trace file on startup (requires configuration).

## Documentation

Additional documentation:
- [Debugging Guide](DEBUGGING_GUIDE.md) - Deep dive into the tracing architecture and implementation
- [Source Code Comments](./trace/reader.py) - Detailed implementation notes

## Version

- **Current Version**: 0.2.0
- **Author**: Markus Gaasedelen
- **Date**: 2021
- **IDA Compatibility**: 9.0, 9.2
- **Qt**: Qt6 (PySide6)

## License

Tenet is provided as-is for security research and educational purposes.

## Credits

- Original Tenet author: Markus Gaasedelen
- ARM64 support contributed by the community
- IDA 9.2 compatibility updates

## Support

For issues, questions, or contributions:
- Check the [Debugging Guide](DEBUGGING_GUIDE.md) for technical details
- Review existing issues and documentation
- Examine the source code comments in `trace/reader.py`
