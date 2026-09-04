#include "util.h"
#include <jni.h>
#include <juice/juice.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct raw_mux {
    JavaVM *vm;
    jobject listener;
    jmethodID dispatch;
    char *address;
    int port;
};

static bool raw_packet(const void *data, size_t size, const char *address, uint16_t port, void *ptr) {
    struct raw_mux *mux = ptr;
    if (size > 65535) return false;
    JNIEnv *env = NULL;
    bool attached = false;
    jint state = (*mux->vm)->GetEnv(mux->vm, (void **)&env, JNI_VERSION_1_6);
    if (state == JNI_EDETACHED) {
        if ((*mux->vm)->AttachCurrentThread(mux->vm, (void **)&env, NULL) != JNI_OK) return false;
        attached = true;
    } else if (state != JNI_OK) return false;
    bool accepted = false;
    if ((*env)->PushLocalFrame(env, 4) == 0) {
        jbyteArray packet = (*env)->NewByteArray(env, (jsize)size);
        if (packet) {
            (*env)->SetByteArrayRegion(env, packet, 0, (jsize)size, data);
            jstring host = (*env)->ExceptionCheck(env) ? NULL : (*env)->NewStringUTF(env, address);
            if (host) accepted = (*env)->CallBooleanMethod(env, mux->listener, mux->dispatch, packet, host, (jint)port);
        }
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); accepted = false; }
        (*env)->PopLocalFrame(env, NULL);
    } else if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (attached) (*mux->vm)->DetachCurrentThread(mux->vm);
    return accepted;
}

JNIEXPORT jlong JNICALL Java_tel_schich_libdatachannel_RawUdpMuxListener_openNative(
    JNIEnv *env, jobject self, jstring address, jint port) {
    struct raw_mux *mux = calloc(1, sizeof(*mux));
    if (!mux) return 0;
    const char *host = (*env)->GetStringUTFChars(env, address, NULL);
    if (!host) { free(mux); return 0; }
    mux->address = strdup(host);
    (*env)->ReleaseStringUTFChars(env, address, host);
    mux->port = port;
    (*env)->GetJavaVM(env, &mux->vm);
    mux->listener = (*env)->NewGlobalRef(env, self);
    jclass clazz = (*env)->GetObjectClass(env, self);
    mux->dispatch = clazz ? (*env)->GetMethodID(env, clazz, "dispatch", "([BLjava/lang/String;I)Z") : NULL;
    if (clazz) (*env)->DeleteLocalRef(env, clazz);
    if (!mux->address || !mux->listener || !mux->dispatch || (*env)->ExceptionCheck(env) ||
        juice_mux_listen_raw(mux->address, port, raw_packet, mux) != 0) {
        if (mux->listener) (*env)->DeleteGlobalRef(env, mux->listener);
        free(mux->address);
        free(mux);
        return 0;
    }
    return (jlong)(intptr_t)mux;
}

JNIEXPORT void JNICALL Java_tel_schich_libdatachannel_RawUdpMuxListener_closeNative(
    JNIEnv *env, jclass clazz, jlong handle) {
    struct raw_mux *mux = (struct raw_mux *)(intptr_t)handle;
    // Registry locking waits for an in-flight callback before releasing JNI refs.
    if (juice_mux_listen_raw(mux->address, mux->port, NULL, NULL) != 0) {
        throw_native_exception(env, "Failed to close raw UDP mux");
        return;
    }
    (*env)->DeleteGlobalRef(env, mux->listener);
    free(mux->address);
    free(mux);
}

JNIEXPORT jlongArray JNICALL Java_tel_schich_libdatachannel_RawUdpMuxListener_statsNative(
    JNIEnv *env, jclass clazz, jlong handle) {
    struct raw_mux *mux = (struct raw_mux *)(intptr_t)handle;
    juice_mux_stats_t stats;
    if (juice_mux_get_stats(mux->address, mux->port, &stats) != 0) {
        throw_native_exception(env, "Raw UDP mux statistics unavailable");
        return NULL;
    }
    jlong values[] = {(jlong)stats.received, (jlong)stats.rejected, stats.agents, stats.mapped_tuples};
    jlongArray result = (*env)->NewLongArray(env, 4);
    if (result) (*env)->SetLongArrayRegion(env, result, 0, 4, values);
    return result;
}
