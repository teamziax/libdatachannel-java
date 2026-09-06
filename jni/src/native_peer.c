#include "callback.h"
#include "util.h"
#include <jni-c-to-java.h>
#include <jni-java-to-c.h>
#include <jni.h>
#include <rtc/rtc.h>
#include <stdlib.h>

void RTC_API handle_local_description(int pc, const char* sdp, const char* type, void* ptr) {
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onLocalDescription_cstr, sdp, type);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetLocalDescriptionCallback, handle_local_description)

void RTC_API handle_local_candidate(int pc, const char* candidate, const char* mediaId, void* ptr) {
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onLocalCandidate_cstr, candidate, mediaId);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetLocalCandidateCallback, handle_local_candidate)

void RTC_API handle_state_change(int pc, rtcState state, void* ptr) {
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onStateChange, state);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetStateChangeCallback, handle_state_change)

void RTC_API handle_ice_state_change(int pc, rtcIceState state, void* ptr) {
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onIceStateChange, state);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetIceStateChangeCallback, handle_ice_state_change)

void RTC_API handle_gathering_state_change(int pc, rtcGatheringState state, void* ptr) {
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onGatheringStateChange, state);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetGatheringStateChangeCallback, handle_gathering_state_change)

void RTC_API handle_signaling_state_change(int pc, rtcSignalingState state, void* ptr) {
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onSignalingStateChange, state);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetSignalingStateChangeCallback, handle_signaling_state_change)

void RTC_API handle_data_channel(int pc, int channelHandle, void* ptr) {
    rtcSetUserPointer(channelHandle, ptr);
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onDataChannel, channelHandle);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetDataChannelCallback, handle_data_channel)

void RTC_API handle_track(int pc, int trackHandle, void* ptr) {
    rtcSetUserPointer(trackHandle, ptr);
    DISPATCH_JNI(call_tel_schich_libdatachannel_PeerConnectionListener_onTrack, trackHandle);
}
SET_CALLBACK_INTERFACE_IMPL(rtcSetTrackCallback, handle_track)

struct incoming_peer {
    int listener;
    uint64_t request_id;
    const char *remote_sdp;
    rtcLocalDescriptionInit local_description;
    int pc;
};

static jint create_peer(JNIEnv* env, jclass clazz,
                                                                            jobjectArray iceServers, jstring proxyServer,
                                                                            jstring bindAddress, jint certificateType,
                                                                            jint iceTransportPolicy,
                                                                            jboolean enableIceTcp,
                                                                            jboolean enableIceUdpMux,
                                                                            jboolean disableAutoNegotiation,
                                                                            jboolean forceMediaTransport,
                                                                            jshort portRangeBegin, jshort portRangeEnd,
                                                                            jint mtu, jint maxMessageSize, jstring certificateFile, jstring keyFile, jstring keyPassword, struct incoming_peer *incoming) {
    rtcConfiguration config = {
            .certificateType = certificateType,
            .iceTransportPolicy = iceTransportPolicy,
            .enableIceTcp = enableIceTcp,
            .enableIceUdpMux = enableIceUdpMux,
            .disableAutoNegotiation = disableAutoNegotiation,
            .forceMediaTransport = forceMediaTransport,
            .portRangeBegin = portRangeBegin,
            .portRangeEnd = portRangeEnd,
            .mtu = mtu,
            .maxMessageSize = maxMessageSize,
    };

    jstring* serverStrings = NULL;

    if (iceServers != NULL) {
        config.iceServersCount = (*env)->GetArrayLength(env, iceServers);
        if (config.iceServersCount > 0) {
            config.iceServers = malloc(sizeof(char*) * config.iceServersCount);
            serverStrings = malloc(sizeof(jstring) * config.iceServersCount);
            if (config.iceServers == NULL || serverStrings == NULL) {
                free(config.iceServers);
                free(serverStrings);
                throw_native_exception(env, "Failed to allocate for ice servers!");
                return EXCEPTION_THROWN;
            }

            for (int i = 0; i < config.iceServersCount; i++) {
                serverStrings[i] = (*env)->GetObjectArrayElement(env, iceServers, i);// we need a reference to release later
                config.iceServers[i] = (*env)->GetStringUTFChars(env, serverStrings[i], NULL);
                if (config.iceServers[i] == NULL) {
                    // release everything and throw an exception
                    for (int j = 0; j < i; j++) {
                        (*env)->ReleaseStringUTFChars(env, serverStrings[j], config.iceServers[j]);
                    }
                    free(config.iceServers);
                    free(serverStrings);
                    throw_native_exception(env, "Failed to get ice server string!");
                    return EXCEPTION_THROWN;
                }
            }
        }
    }

    if (proxyServer != NULL) {
        config.proxyServer = (*env)->GetStringUTFChars(env, proxyServer, NULL);
    }
    if (bindAddress != NULL) {
        config.bindAddress = (*env)->GetStringUTFChars(env, bindAddress, NULL);
    }

    const char *certificate = certificateFile ? (*env)->GetStringUTFChars(env, certificateFile, NULL) : NULL;
    const char *key = keyFile && !(*env)->ExceptionCheck(env) ? (*env)->GetStringUTFChars(env, keyFile, NULL) : NULL;
    const char *pass = keyPassword && !(*env)->ExceptionCheck(env) ? (*env)->GetStringUTFChars(env, keyPassword, NULL) : NULL;
    config.certificatePemFile = certificate;
    config.keyPemFile = key;
    config.keyPemPass = pass;
    jint result = EXCEPTION_THROWN;
    if (!(*env)->ExceptionCheck(env)) {
        if (incoming) result = rtcPrepareIceUdpMuxPeer(incoming->listener, incoming->request_id,
            &config, incoming->remote_sdp, &incoming->local_description, &incoming->pc);
        else result = (jint) rtcCreatePeerConnection(&config);
    }
    if (pass) (*env)->ReleaseStringUTFChars(env, keyPassword, pass);
    if (certificate) (*env)->ReleaseStringUTFChars(env, certificateFile, certificate);
    if (key) (*env)->ReleaseStringUTFChars(env, keyFile, key);

    if (proxyServer != NULL) {
        (*env)->ReleaseStringUTFChars(env, proxyServer, config.proxyServer);
    }
    if (bindAddress != NULL) {
        (*env)->ReleaseStringUTFChars(env, bindAddress, config.bindAddress);
    }

    if (config.iceServers != NULL && config.iceServersCount > 0) {
        for (int i = 0; i < config.iceServersCount; i++) {
            (*env)->ReleaseStringUTFChars(env, serverStrings[i], config.iceServers[i]);
        }
        free(config.iceServers);
        free(serverStrings);
    }

    return result;
}


JNIEXPORT jint JNICALL
Java_tel_schich_libdatachannel_LibDataChannelNative_rtcCreatePeerConnection(JNIEnv* env, jclass clazz,
                                                                            jobjectArray iceServers, jstring proxyServer,
                                                                            jstring bindAddress, jint certificateType,
                                                                            jint iceTransportPolicy,
                                                                            jboolean enableIceTcp,
                                                                            jboolean enableIceUdpMux,
                                                                            jboolean disableAutoNegotiation,
                                                                            jboolean forceMediaTransport,
                                                                            jshort portRangeBegin, jshort portRangeEnd,
                                                                            jint mtu, jint maxMessageSize) {
    return create_peer(env, clazz, iceServers, proxyServer, bindAddress, certificateType, iceTransportPolicy, enableIceTcp, enableIceUdpMux, disableAutoNegotiation, forceMediaTransport, portRangeBegin, portRangeEnd, mtu, maxMessageSize, NULL, NULL, NULL, NULL);
}

JNIEXPORT jint JNICALL
Java_tel_schich_libdatachannel_LibDataChannelNative_rtcCreatePeerConnectionWithIdentity(JNIEnv* env, jclass clazz,
                                                                            jobjectArray iceServers, jstring proxyServer,
                                                                            jstring bindAddress, jint certificateType,
                                                                            jint iceTransportPolicy,
                                                                            jboolean enableIceTcp,
                                                                            jboolean enableIceUdpMux,
                                                                            jboolean disableAutoNegotiation,
                                                                            jboolean forceMediaTransport,
                                                                            jshort portRangeBegin, jshort portRangeEnd,
                                                                            jint mtu, jint maxMessageSize, jstring certificateFile, jstring keyFile, jstring keyPassword) {
    return create_peer(env, clazz, iceServers, proxyServer, bindAddress, certificateType, iceTransportPolicy, enableIceTcp, enableIceUdpMux, disableAutoNegotiation, forceMediaTransport, portRangeBegin, portRangeEnd, mtu, maxMessageSize, certificateFile, keyFile, keyPassword, NULL);
}

JNIEXPORT jint JNICALL
Java_tel_schich_libdatachannel_LibDataChannelNative_rtcClosePeerConnection(JNIEnv* env, jclass clazz, jint peerHandle) {
    return rtcClosePeerConnection(peerHandle);
}

JNIEXPORT jint JNICALL
Java_tel_schich_libdatachannel_LibDataChannelNative_rtcDeletePeerConnection(JNIEnv* env, jclass clazz,
                                                                            jint peerHandle) {
    struct jvm_callback* callback = rtcGetUserPointer(peerHandle);
    jint result = rtcDeletePeerConnection(peerHandle);
    if (result == RTC_ERR_SUCCESS && callback != NULL) {
        free_callback(env, callback);
    }

    return result;
}


JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcSetLocalDescription(JNIEnv* env, jclass clazz, jint peerHandle, jstring type) {
    const char* c_type = (*env)->GetStringUTFChars(env, type, NULL);
    if (c_type == NULL) {
        THROW_FAILED_GET_STR(env, type);
        return EXCEPTION_THROWN;
    }
    int result = WRAP_ERROR(env, rtcSetLocalDescription(peerHandle, c_type));
    (*env)->ReleaseStringUTFChars(env, type, c_type);
    return result;
}

JNIEXPORT jstring JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetLocalDescription(JNIEnv* env, jclass clazz, jint peerHandle) {
    return GET_DYNAMIC_STRING(env, rtcGetLocalDescription, peerHandle);
}

JNIEXPORT jstring JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetLocalDescriptionType(JNIEnv* env, jclass clazz, jint peerHandle) {
    return GET_DYNAMIC_STRING(env, rtcGetLocalDescriptionType, peerHandle);
}

JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcSetRemoteDescription(JNIEnv* env, jclass clazz, jint peerHandle, jstring sdp, jstring type) {
    const char* c_sdp = (*env)->GetStringUTFChars(env, sdp, NULL);
    if (c_sdp == NULL) {
        THROW_FAILED_GET_STR(env, sdp);
        return EXCEPTION_THROWN;
    }
    const char* c_type = (*env)->GetStringUTFChars(env, type, NULL);
    if (c_type == NULL) {
        (*env)->ReleaseStringUTFChars(env, sdp, c_sdp);
        THROW_FAILED_GET_STR(env, type);
        return EXCEPTION_THROWN;
    }
    int result = WRAP_ERROR(env, rtcSetRemoteDescription(peerHandle, c_sdp, c_type));
    (*env)->ReleaseStringUTFChars(env, sdp, c_sdp);
    (*env)->ReleaseStringUTFChars(env, type, c_type);
    return result;
}

JNIEXPORT jstring JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetRemoteDescription(JNIEnv* env, jclass clazz, jint peerHandle) {
    return GET_DYNAMIC_STRING(env, rtcGetRemoteDescription, peerHandle);
}

JNIEXPORT jstring JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetRemoteDescriptionType(JNIEnv* env, jclass clazz, jint peerHandle) {
    return GET_DYNAMIC_STRING(env, rtcGetRemoteDescriptionType, peerHandle);
}

JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcAddRemoteCandidate(JNIEnv* env, jclass clazz, jint peerHandle, jstring candidate, jstring mediaId) {
    const char* c_candidate = NULL;
    if (candidate != NULL) {
        c_candidate = (*env)->GetStringUTFChars(env, candidate, NULL);
        if (c_candidate == NULL) {
            THROW_FAILED_GET_STR(env, candidate);
            return EXCEPTION_THROWN;
        }
    }
    const char* c_mediaId = NULL;
    if (mediaId != NULL) {
        c_mediaId = (*env)->GetStringUTFChars(env, mediaId, NULL);
        if (c_mediaId == NULL) {
            if (c_candidate != NULL) {
                (*env)->ReleaseStringUTFChars(env, candidate, c_candidate);
            }
            THROW_FAILED_GET_STR(env, mediaId);
            return EXCEPTION_THROWN;
        }
    }

    int result = rtcAddRemoteCandidate(peerHandle, c_candidate, c_mediaId);
    if (c_candidate != NULL) {
        (*env)->ReleaseStringUTFChars(env, candidate, c_candidate);
    }
    if (c_mediaId != NULL) {
        (*env)->ReleaseStringUTFChars(env, mediaId, c_mediaId);
    }

    return result;
}

JNIEXPORT jstring JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetLocalAddress(JNIEnv* env, jclass clazz, jint peerHandle) {
    return GET_DYNAMIC_STRING(env, rtcGetLocalAddress, peerHandle);
}

JNIEXPORT jstring JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetRemoteAddress(JNIEnv* env, jclass clazz, jint peerHandle) {
    return GET_DYNAMIC_STRING(env, rtcGetRemoteAddress, peerHandle);
}

JNIEXPORT jobject JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetSelectedCandidatePair(JNIEnv* env, jclass clazz, jint peerHandle) {
    int bufSize = 50;
    char* local = malloc(bufSize);
    if (local == NULL) {
        THROW_FAILED_MALLOC(env, local);
        return NULL;
    }
    char* remote = malloc(bufSize);
    if (remote == NULL) {
        free(local);
        THROW_FAILED_MALLOC(env, remote);
        return NULL;
    }

    int result = rtcGetSelectedCandidatePair(peerHandle, local, bufSize, remote, bufSize);
    if (result < 0) {
        free(local);
        free(remote);
        WRAP_ERROR(env, result);
        return NULL;
    }

    jobject candidatePair = call_tel_schich_libdatachannel_CandidatePair_parse_cstr(env, local, remote);

    free(local);
    free(remote);

    return candidatePair;
}

JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_setupPeerConnectionListener(JNIEnv* env, jclass clazz, jint peerHandle, jobject listener) {
    struct jvm_callback* jvm_callback = allocate_callback(env, listener);
    if (jvm_callback == NULL) {
        return EXCEPTION_THROWN;
    }
    rtcSetUserPointer(peerHandle, jvm_callback);

    return RTC_ERR_SUCCESS;
}
JNIEXPORT jint JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcSetLocalDescriptionWithIce(
    JNIEnv *env, jclass clazz, jint peer, jstring type, jstring ufrag, jstring password) {
    const char *t = type ? (*env)->GetStringUTFChars(env, type, NULL) : NULL;
    if (type && !t) return EXCEPTION_THROWN;
    const char *u = (*env)->GetStringUTFChars(env, ufrag, NULL);
    const char *p = u ? (*env)->GetStringUTFChars(env, password, NULL) : NULL;
    rtcLocalDescriptionInit init = {.iceUfrag = u, .icePwd = p};
    int result = p ? rtcSetLocalDescriptionEx(peer, t, &init) : EXCEPTION_THROWN;
    if (p) (*env)->ReleaseStringUTFChars(env, password, p);
    if (u) (*env)->ReleaseStringUTFChars(env, ufrag, u);
    if (t) (*env)->ReleaseStringUTFChars(env, type, t);
    return result;
}

JNIEXPORT jlong JNICALL Java_tel_schich_libdatachannel_LibDataChannelNative_rtcGetPeerConnectionCreationAttempts(
    JNIEnv *env, jclass clazz) { return (jlong)rtcGetPeerConnectionCreationAttempts(); }

JNIEXPORT jint JNICALL
Java_tel_schich_libdatachannel_LibDataChannelNative_rtcClosePeerConnectionAndWait(JNIEnv* env, jclass clazz, jint peerHandle, jint timeoutMs) {
    return rtcClosePeerConnectionAndWait(peerHandle, timeoutMs);
}

JNIEXPORT jintArray JNICALL Java_tel_schich_libdatachannel_IceUdpMuxListener_prepareConfiguredNative(
    JNIEnv *env, jclass clazz, jint listener, jlong requestId,
    jobjectArray iceServers, jstring proxyServer, jstring bindAddress, jint certificateType,
    jint iceTransportPolicy, jboolean enableIceTcp, jboolean enableIceUdpMux,
    jboolean disableAutoNegotiation, jboolean forceMediaTransport,
    jshort portRangeBegin, jshort portRangeEnd, jint mtu, jint maxMessageSize,
    jstring certificateFile, jstring keyFile, jstring keyPassword,
    jstring remoteDescription, jstring localUfrag, jstring localPassword) {
    // Allocate the result before creating anything: ownership must never be lost on allocation failure.
    jintArray result = (*env)->NewIntArray(env, 2);
    if (!result) return NULL;
    struct incoming_peer incoming = {.listener = listener, .request_id = (uint64_t)requestId, .pc = -1};
    incoming.remote_sdp = (*env)->GetStringUTFChars(env, remoteDescription, NULL);
    incoming.local_description.iceUfrag = !(*env)->ExceptionCheck(env) ? (*env)->GetStringUTFChars(env, localUfrag, NULL) : NULL;
    incoming.local_description.icePwd = !(*env)->ExceptionCheck(env) ? (*env)->GetStringUTFChars(env, localPassword, NULL) : NULL;
    jint status = EXCEPTION_THROWN;
    if (!(*env)->ExceptionCheck(env)) status = create_peer(env, clazz, iceServers, proxyServer, bindAddress,
        certificateType, iceTransportPolicy, enableIceTcp, enableIceUdpMux, disableAutoNegotiation,
        forceMediaTransport, portRangeBegin, portRangeEnd, mtu, maxMessageSize,
        certificateFile, keyFile, keyPassword, &incoming);
    if (incoming.remote_sdp) (*env)->ReleaseStringUTFChars(env, remoteDescription, incoming.remote_sdp);
    if (incoming.local_description.iceUfrag) (*env)->ReleaseStringUTFChars(env, localUfrag, incoming.local_description.iceUfrag);
    if (incoming.local_description.icePwd) (*env)->ReleaseStringUTFChars(env, localPassword, incoming.local_description.icePwd);
    if (!(*env)->ExceptionCheck(env)) {
        jint values[] = {status, incoming.pc};
        (*env)->SetIntArrayRegion(env, result, 0, 2, values);
    }
    return result;
}
