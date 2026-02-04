# tenet/trace/arch/aarch64.py
class ArchAArch64:
    """
    AArch64 CPU Architecture Definition.
    """
    MAGIC = 0x41415268  # ASCII "AARH" - Placeholder, confirm if a standard exists or use this

    POINTER_SIZE = 8

    IP = "PC"  # Program Counter in AArch64
    SP = "SP"  # Stack Pointer in AArch64

    REGISTERS = \
    [
        # General-purpose registers (X0-X30)
        "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
        "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15",
        "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23",
        "X24", "X25", "X26", "X27", "X28", "X29", "X30", # X29 is Frame Pointer (FP), X30 is Link Register (LR)

        # Special registers
        "SP", # Stack Pointer
        "PC", # Program Counter

        # Potentially add PSTATE/CPSR if needed by the trace format/analysis
        # "PSTATE"
    ]