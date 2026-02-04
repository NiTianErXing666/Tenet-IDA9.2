#ifndef QBDI_TRACE_C_H
#define QBDI_TRACE_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * C 风格接口：使用指定模式进行 trace
 *
 * @param funcPtr    要 trace 的函数指针
 * @param args       参数数组（C 风格指针）
 * @param arg_count  参数个数
 * @param retVal     输出参数：返回值（指针）
 * @param modeType   trace 模式类型
 * @param outputMode 日志输出模式 (0=BOTH, 1=FILE, 2=LOGCAT)
 */
__attribute__((visibility("default")))
void qbdi_trace_with_mode_c(
    unsigned long funcPtr,
    const unsigned long* args,
    size_t arg_count,
    unsigned long* retVal,
    int modeType,
    int outputMode
);

// 简化版本：使用默认输出模式 (BOTH)
#define qbdi_trace_with_mode_c_simple(funcPtr, args, arg_count, retVal, modeType) \
    qbdi_trace_with_mode_c(funcPtr, args, arg_count, retVal, modeType, 0)

// 兼容接口（默认 CALL 模式，默认输出模式）
#define qbdi_trace_with_args_c(funcPtr, args, arg_count, retVal) \
    qbdi_trace_with_mode_c(funcPtr, args, arg_count, retVal, 0, 0)

#ifdef __cplusplus
}
#endif

#endif // QBDI_TRACE_C_H
