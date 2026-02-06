# Trace Tenet - Android Trace Analysis Tools

A comprehensive trace analysis toolkit for Android reverse engineering, featuring native trace generation and IDA Pro trace visualization.

## Project Structure

```
trace_tenet/
├── trace_tools/
│   ├── libtrace.so           # Native trace library (push to /data/local/tmp/)
│   ├── trace_helper.js       # Frida script using libtrace.so
│   └── tenet_tracer_v2.js    # Frida Stalker-based tracer
├── tenet/                    # Tenet IDA Pro plugin
│   ├── integration/          # IDA integration
│   ├── trace/                # Trace file reader & parser
│   └── ui/                   # User interface
└── tenet_plugin.py           # IDA plugin entry point
```

## Features

- **Native Trace Library** (`libtrace.so`) - High-performance trace generation using QBDI
- **Frida Integration** - Two tracing methods (libtrace.so / Stalker)
- **Tenet Format** - Compatible with Tenet trace explorer for IDA Pro
- **IDA Pro Plugin** - Visualize execution traces with memory/register tracking

---

## Part 1: Trace Generation on Android

### Method A: Using libtrace.so (Recommended)

#### 1. Push libtrace.so to Device

```bash
adb push trace_tools/libtrace.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/libtrace.so
```

#### 2. Configure trace_helper.js

Edit `trace_tools/trace_helper.js` and modify the `CONFIG` object:

```javascript
var CONFIG = {
    // Path to libtrace.so on device
    traceLibraryPath: "/data/local/tmp/libtrace.so",

    // Trace mode
    // 0 = CALL_ONLY      - Track function calls only
    // 1 = FULL_TRACE     - Track all instructions
    // 2 = SVC_TRACE      - Track SVC instructions
    // 3 = TENET_TRACE    - Generate Tenet-compatible format
    currentMode: 3,

    // Output mode
    // 0 = FILE      - Save to file only
    // 1 = CONSOLE   - Print to logcat only
    // 2 = BOTH      - Both file and console
    outputMode: 0,

    // Target configuration
    targets: [
        {
            moduleName: "libtarget.so",      // Target SO module name
            hooks: [
                {
                    type: "offset",           // Hook by offset
                    offset: 0x1234,          // Function offset
                    signature: ["pointer", "pointer"],  // Function signature
                    replace: true,           // Replace function
                    name: "target_function"  // Function name for logging
                }
            ]
        }
    ]
};
```

#### 3. Run Frida with trace_helper.js

```bash
# Spawn application
frida -U -f com.example.app -l trace_tools/trace_helper.js --no-pause

# Or attach to running process
frida -U com.example.app -l trace_tools/trace_helper.js
```

The trace file will be generated in `/data/local/tmp/` by default.

---

### Method B: Using Frida Stalker (Simpler)

The `tenet_tracer_v2.js` script uses Frida's built-in Stalker for tracing. It automatically detects the package name and saves the trace to the app's data directory.

#### 1. Configure tenet_tracer_v2.js

Edit `trace_tools/tenet_tracer_v2.js`:

```javascript
// Target configuration
const TARGET_MODULE = "libtarget.so";      // Target SO module
const TARGET_OFFSET = 0x1234;              // Function offset to trace
const MAX_INSTRUCTIONS = 900000000;        // Instruction limit
const PACKAGE_NAME = "com.example.app";    // Optional: null for auto-detect
const OUTPUT_FILENAME = "tenet.trace";     // Output filename
```

#### 2. Run the Tracer

```bash
# Spawn the application
frida -U -f com.example.app -l trace_tools/tenet_tracer_v2.js --no-pause

# Or attach to running process
frida -U com.example.app -l trace_tools/tenet_tracer_v2.js
```

#### 3. Trace Output Location

The script automatically saves the trace file to:
- Primary: `/data/data/<package_name>/tenet.trace`
- Fallback: `/data/local/tmp/tenet.trace`

Pull the trace file:

```bash
# After tracing is complete
adb pull /data/data/com.example.app/tenet.trace ./
```

---

## Part 2: Installing Tenet Plugin in IDA Pro

### Step 1: Locate IDA Plugins Directory

**Windows:**
```
C:\Users\<username>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\
```

**Linux:**
```
~/.idapro/plugins/
```

**macOS:**
```
~/.idapro/plugins/
```

### Step 2: Copy Tenet Files

Copy the entire `tenet` directory and plugin file:

```bash
# Windows example
xcopy /E /I tenet C:\Users\<username>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\tenet
copy tenet_plugin.py C:\Users\<username>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\
```

Or manually:
1. Copy `tenet/` folder to IDA `plugins/` directory
2. Copy `tenet_plugin.py` to IDA `plugins/` directory

### Step 3: Verify Installation

1. Restart IDA Pro
2. Open any IDB database
3. Check `Edit -> Plugins` menu for "Tenet" (or it loads automatically)

---

## Part 3: Using Tenet in IDA Pro

### Loading a Trace File

1. Open your IDB database in IDA Pro
2. Ensure the target SO is loaded at the correct base address
3. Load trace via: `File -> Load -> Tenet Trace` (or use the plugin menu)
4. Select your `tenet.trace` file

### Tenet UI Features

- **Trace View** - Step through execution trace
- **Register View** - View register changes over time
- **Memory View** - Track memory reads/writes
- **Breakpoint View** - Manage execution breakpoints
- **Hex View** - Examine memory regions

### Keyboard Shortcuts

Once loaded, Tenet provides standard trace controls:
- `F5` / `F9` - Start/Continue trace playback
- `F7` - Step into
- `F8` - Step over
- Navigation hotkeys for jumping to addresses

---

## Configuration Examples

### Example 1: Tracing an Encryption Function

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

### Example 2: Multiple Functions

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

## Troubleshooting

### libtrace.so Issues

**Error: `dlopen failed`**
```bash
# Check file permissions
adb shell ls -la /data/local/tmp/libtrace.so

# Ensure executable
adb shell chmod 755 /data/local/tmp/libtrace.so

# Check architecture compatibility (arm64 vs arm)
adb shell file /data/local/tmp/libtrace.so
```

### Frida Stalker Issues

**Trace file not created:**
- Check write permissions: `adb shell ls -la /data/data/<pkg>/`
- Manually specify `PACKAGE_NAME` if auto-detection fails
- Check logcat for errors: `adb logcat | grep -i frida`

### IDA Plugin Issues

**Plugin not loading:**
- Check IDA Python console: `View -> Open subviews -> Python`
- Verify `tenet` folder structure is intact
- Check IDA version compatibility (tested with IDA Pro 7.x+)

**Trace file won't load:**
- Ensure SO base address matches (IDA view vs trace file header)
- Verify trace file format is correct (should start with `# SO:` header)
- Check for corrupted trace files (size should be reasonable)

---

## Architecture Support

| Architecture | libtrace.so | Tenet Plugin |
|-------------|-------------|--------------|
| ARM64       | ✓           | ✓            |
| ARM32       | ✓           | ✓            |
| x86         | -           | ✓            |
| x64         | -           | ✓            |

---

## References

- Tenet: https://github.com/gaasedelen/tenet
- Frida: https://frida.re/docs/
- QBDI: https://qbdi.quarkslab.com/

---

## License

This project is based on [Tenet](https://github.com/gaasedelen/tenet) by gaasedelen.
Please refer to the original project for license information.

---

## Contributing

This is a modified/custom version of Tenet for Android trace analysis.
For issues or questions, please refer to the original Tenet repository.
