#include "util.hpp"
#include <jni.h>
#include <rtc/rtc.h>
#include <cstdint>

extern "C" JNIEXPORT jlong JNICALL Java_tel_schich_libdatachannel_UdpSendLimits_clockNative(JNIEnv* env, jclass) {
    uint64_t now;
    if (rtcGetUdpMonotonicTimeMs(&now) != RTC_ERR_SUCCESS || now > INT64_MAX) {
        throw_native_exception(env, "Native UDP monotonic clock unavailable"); return -1;
    }
    return static_cast<jlong>(now);
}
extern "C" JNIEXPORT jlongArray JNICALL Java_tel_schich_libdatachannel_UdpSendLimits_statsNative(JNIEnv* env, jclass, jint pc) {
    rtcUdpSendStats stats{};
    const int result = rtcGetUdpSendStats(pc, &stats);
    if (result == RTC_ERR_NOT_AVAIL) return nullptr;
    if (result != RTC_ERR_SUCCESS) {
        throw_native_exception(env, "Native UDP send statistics unavailable"); return nullptr;
    }
    const jlong values[] = {static_cast<jlong>(stats.reservedDatagrams), static_cast<jlong>(stats.sentDatagrams),
        static_cast<jlong>(stats.sentBytes), static_cast<jlong>(stats.rejectedDatagrams), static_cast<jlong>(stats.lastRejection)};
    jlongArray array = env->NewLongArray(5);
    if (array) env->SetLongArrayRegion(array, 0, 5, values);
    return array;
}
