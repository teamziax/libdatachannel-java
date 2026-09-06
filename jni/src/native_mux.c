#include "util.h"
#include <jni.h>
#include <rtc/rtc.h>
#include <stdint.h>
#include <stdlib.h>

struct ice_mux {
    int listener;
    jobject owner;
    jmethodID dispatch;
};

JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_listenerIdNative(
    JNIEnv *env, jclass clazz, jlong handle) {
    return ((struct ice_mux *)(intptr_t)handle)->listener;
}

static void RTC_API incoming_request(int listener, const rtcIceUdpMuxRequest *request, void *ptr) {
    struct ice_mux *mux = ptr;
    JNIEnv *env = get_jni_env();
    bool queued = false;
    if (env && (*env)->PushLocalFrame(env, 4) == 0) {
        jstring local = (*env)->NewStringUTF(env, request->localUfrag);
        jstring remote = !(*env)->ExceptionCheck(env) ? (*env)->NewStringUTF(env, request->remoteUfrag) : NULL;
        jstring address = !(*env)->ExceptionCheck(env) ? (*env)->NewStringUTF(env, request->remoteAddress) : NULL;
        if (!(*env)->ExceptionCheck(env)) queued = (*env)->CallBooleanMethod(env, mux->owner,
            mux->dispatch, (jlong)request->id, local, remote, address, (jint)request->remotePort);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); queued = false; }
        (*env)->PopLocalFrame(env, NULL);
    } else if (env && (*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (!queued) rtcRejectIceUdpMuxRequest(listener, request->id);
}

JNIEXPORT jlong JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_openNative(
    JNIEnv *env, jobject self, jstring address, jint port, jint maxPending, jint timeoutMs) {
    struct ice_mux *mux = calloc(1, sizeof(*mux));
    if (!mux) return 0;
    mux->listener = -1;
    mux->owner = (*env)->NewGlobalRef(env, self);
    jclass clazz = !(*env)->ExceptionCheck(env) ? (*env)->GetObjectClass(env, self) : NULL;
    mux->dispatch = clazz ? (*env)->GetMethodID(env, clazz, "dispatch", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Z") : NULL;
    if (clazz) (*env)->DeleteLocalRef(env, clazz);
    const char *host = !(*env)->ExceptionCheck(env) ? (*env)->GetStringUTFChars(env, address, NULL) : NULL;
    if (host && mux->owner && mux->dispatch) {
        rtcIceUdpMuxListenerConfiguration config = {.bindAddress = host, .port = (uint16_t)port,
            .maxPendingRequests = (unsigned int)maxPending, .requestTimeoutMs = (unsigned int)timeoutMs};
        mux->listener = rtcCreateIceUdpMuxListener(&config, incoming_request, mux);
    }
    if (host) (*env)->ReleaseStringUTFChars(env, address, host);
    if (mux->listener < 0) {
        if (mux->owner) (*env)->DeleteGlobalRef(env, mux->owner);
        free(mux);
        return 0;
    }
    return (jlong)(intptr_t)mux;
}

JNIEXPORT void JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_closeNative(
    JNIEnv *env, jclass clazz, jlong handle) {
    struct ice_mux *mux = (struct ice_mux *)(intptr_t)handle;
    if (rtcDeleteIceUdpMuxListener(mux->listener) != RTC_ERR_SUCCESS) {
        throw_native_exception(env, "Failed to close ICE UDP mux listener");
        return;
    }
    // Native deletion waits for in-flight metadata callbacks before releasing this reference.
    (*env)->DeleteGlobalRef(env, mux->owner);
    free(mux);
}

JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_acceptNative(
    JNIEnv *env, jclass clazz, jint listener, jlong requestId, jint peer) {
    return rtcAcceptIceUdpMuxPeer(listener, (uint64_t)requestId, peer);
}

JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_rejectNative(
    JNIEnv *env, jclass clazz, jint listener, jlong requestId) {
    return rtcRejectIceUdpMuxRequest(listener, (uint64_t)requestId);
}

JNIEXPORT jlongArray JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_statsNative(
    JNIEnv *env, jclass clazz, jint listener) {
    rtcIceUdpMuxListenerStats stats;
    if (rtcGetIceUdpMuxListenerStats(listener, &stats) != RTC_ERR_SUCCESS) {
        throw_native_exception(env, "ICE UDP mux statistics unavailable");
        return NULL;
    }
    jlong values[] = {(jlong)stats.received, (jlong)stats.rejected, (jlong)stats.agents,
        (jlong)stats.mappedTuples, (jlong)stats.pendingRequests, (jlong)stats.notifications, (jlong)stats.duplicates};
    jlongArray result = (*env)->NewLongArray(env, 7);
    if (result) (*env)->SetLongArrayRegion(env, result, 0, 7, values);
    return result;
}
