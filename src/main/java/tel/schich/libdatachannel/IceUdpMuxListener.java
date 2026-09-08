package tel.schich.libdatachannel;

import org.eclipse.jdt.annotation.Nullable;
import tel.schich.jniaccess.JNIAccess;

import java.net.InetAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Accepts incoming ICE connections on one UDP endpoint. Native code retains the
 * first STUN request while the application decides; packets never pass through Java.
 * Accepted peers are caller-owned and should be closed before this listener.
 */
public final class IceUdpMuxListener implements AutoCloseable {
    @FunctionalInterface
    public interface Handler {
        /** Complete with connection settings to accept, or null to reject. */
        CompletionStage<Acceptance> onRequest(Request request) throws Exception;
    }

    /** Parsed, untrusted metadata from an incoming STUN request. */
    public static final class Request {
        private final long id;
        private final String localUfrag, remoteUfrag, remoteAddress;
        private final int remotePort;
        private final CompletableFuture<PeerConnection> completion = new CompletableFuture<>();
        private final AtomicBoolean settling = new AtomicBoolean();
        private final AtomicReference<Throwable> cancellation = new AtomicReference<>();
        private volatile ScheduledFuture<?> timeout;

        private Request(long id, String localUfrag, String remoteUfrag, String remoteAddress, int remotePort) {
            this.id = id;
            this.localUfrag = localUfrag;
            this.remoteUfrag = remoteUfrag;
            this.remoteAddress = remoteAddress;
            this.remotePort = remotePort;
        }

        public long id() { return id; }
        public String localUfrag() { return localUfrag; }
        public String remoteUfrag() { return remoteUfrag; }
        public String remoteAddress() { return remoteAddress; }
        public int remotePort() { return remotePort; }

        /** Completes after acceptance, or after any failed prepared peer has been torn down. */
        public CompletionStage<PeerConnection> completion() { return completion.minimalCompletionStage(); }
    }

    /** Settings returned by application admission. Fingerprint checks remain enabled. */
    public static final class Acceptance {
        final PeerConnectionConfiguration configuration;
        final String remoteDescription, localPassword;
        final @Nullable Path certificate, key;
        final @Nullable String keyPassword;
        final Executor peerExecutor;
        final Consumer<PeerConnection> initializer;
        final Instant expiresAt;
        final @Nullable PeerConnection existingPeer;

        /** @deprecated Use {@link #builder(String, String)}. */
        @Deprecated
        public Acceptance(PeerConnectionConfiguration configuration, String remoteDescription, String localPassword,
                          @Nullable Path certificate, @Nullable Path key, @Nullable String keyPassword,
                          Executor peerExecutor, Consumer<PeerConnection> initializer) {
            this(configuration, remoteDescription, localPassword, certificate, key, keyPassword,
                peerExecutor, initializer, Instant.MAX);
        }

        /** @deprecated Use {@link #builder(String, String)}. */
        @Deprecated
        public Acceptance(PeerConnectionConfiguration configuration, String remoteDescription, String localPassword,
                          @Nullable Path certificate, @Nullable Path key, @Nullable String keyPassword,
                          Executor peerExecutor, Consumer<PeerConnection> initializer, Instant expiresAt) {
            this.configuration = Objects.requireNonNull(configuration, "configuration");
            this.remoteDescription = Objects.requireNonNull(remoteDescription, "remoteDescription");
            this.localPassword = Objects.requireNonNull(localPassword, "localPassword");
            if ((certificate == null) != (key == null)) throw new IllegalArgumentException("Certificate/key must be paired");
            if (keyPassword != null && key == null) throw new IllegalArgumentException("A key password requires an identity");
            this.certificate = certificate;
            this.key = key;
            this.keyPassword = keyPassword;
            this.peerExecutor = Objects.requireNonNull(peerExecutor, "peerExecutor");
            this.initializer = Objects.requireNonNull(initializer, "initializer");
            this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
            this.existingPeer = null;
        }

        private Acceptance(PeerConnection peer, Instant expiresAt) {
            this.configuration = PeerConnectionConfiguration.DEFAULT;
            this.remoteDescription = this.localPassword = "";
            this.certificate = this.key = null;
            this.keyPassword = null;
            this.peerExecutor = Runnable::run;
            this.initializer = ignored -> {};
            this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
            this.existingPeer = Objects.requireNonNull(peer, "peer");
        }

        /** Approve another tuple for a caller-owned peer without replacing its identity or channels. */
        public static Acceptance reuse(PeerConnection peer) { return reuse(peer, Instant.MAX); }
        public static Acceptance reuse(PeerConnection peer, Instant expiresAt) { return new Acceptance(peer, expiresAt); }

        public static Builder builder(String remoteDescription, String localPassword) {
            return new Builder(remoteDescription, localPassword);
        }

        public static final class Builder {
            private final String remoteDescription, localPassword;
            private PeerConnectionConfiguration configuration = PeerConnectionConfiguration.DEFAULT;
            private @Nullable DtlsIdentity identity;
            private Executor peerExecutor = Runnable::run;
            private Consumer<PeerConnection> initializer = ignored -> {};
            private Instant expiresAt = Instant.MAX;

            private Builder(String remoteDescription, String localPassword) {
                this.remoteDescription = Objects.requireNonNull(remoteDescription, "remoteDescription");
                this.localPassword = Objects.requireNonNull(localPassword, "localPassword");
            }
            public Builder configuration(PeerConnectionConfiguration value) { configuration = Objects.requireNonNull(value); return this; }
            public Builder identity(DtlsIdentity value) { identity = Objects.requireNonNull(value); return this; }
            public Builder peerExecutor(Executor value) { peerExecutor = Objects.requireNonNull(value); return this; }
            public Builder initialize(Consumer<PeerConnection> value) { initializer = Objects.requireNonNull(value); return this; }
            public Builder expiresAt(Instant value) { expiresAt = Objects.requireNonNull(value); return this; }
            public Acceptance build() {
                return new Acceptance(configuration, remoteDescription, localPassword,
                    identity == null ? null : identity.certificate(), identity == null ? null : identity.privateKey(),
                    identity == null ? null : identity.password(), peerExecutor, initializer, expiresAt);
            }
        }
    }

    /** Snapshot of native listener activity. Counts belong to this endpoint. */
    public static final class Statistics {
        private final long received, rejected, agents, mappedTuples, pendingRequests, notifications, duplicates;
        private Statistics(long[] values) {
            received = values[0]; rejected = values[1]; agents = values[2]; mappedTuples = values[3];
            pendingRequests = values[4]; notifications = values[5]; duplicates = values[6];
        }
        public long received() { return received; }
        public long rejected() { return rejected; }
        public long agents() { return agents; }
        public long mappedTuples() { return mappedTuples; }
        public long pendingRequests() { return pendingRequests; }
        public long notifications() { return notifications; }
        public long duplicates() { return duplicates; }
    }

    private static final ScheduledThreadPoolExecutor DEADLINES = new ScheduledThreadPoolExecutor(1, task -> {
        Thread thread = new Thread(task, "ice-admission-deadlines");
        thread.setDaemon(true);
        return thread;
    });
    private static final ScheduledThreadPoolExecutor CLEANUP = new ScheduledThreadPoolExecutor(2, task -> {
        Thread thread = new Thread(task, "ice-admission-cleanup");
        thread.setDaemon(true);
        return thread;
    });
    static {
        DEADLINES.setRemoveOnCancelPolicy(true);
        DEADLINES.setKeepAliveTime(30, TimeUnit.SECONDS);
        DEADLINES.allowCoreThreadTimeOut(true);
        CLEANUP.setKeepAliveTime(30, TimeUnit.SECONDS);
        CLEANUP.allowCoreThreadTimeOut(true);
    }

    private final Executor executor;
    private final Handler handler;
    private final int requestTimeoutMillis, maxPendingRequests;
    private final ConcurrentMap<Long, Request> requests = new ConcurrentHashMap<>();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private final ThreadPoolExecutor dispatchQueue;
    private long handle;
    private int listenerId;

    public IceUdpMuxListener(InetAddress bindAddress, int port, Executor executor, Handler handler) {
        this(bindAddress, port, 256, Duration.ofSeconds(5), executor, handler);
    }

    public IceUdpMuxListener(InetAddress bindAddress, int port, int maxPendingRequests, Duration requestTimeout,
                             Executor executor, Handler handler) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Explicit UDP port required");
        if (maxPendingRequests < 1 || maxPendingRequests > 4096) throw new IllegalArgumentException("Pending limit must be 1..4096");
        long timeout = Objects.requireNonNull(requestTimeout, "requestTimeout").toMillis();
        if (timeout < 1 || timeout > 30000) throw new IllegalArgumentException("Request timeout must be 1..30000 ms");
        this.requestTimeoutMillis = (int) timeout;
        this.maxPendingRequests = maxPendingRequests;
        this.executor = Objects.requireNonNull(executor, "executor");
        this.handler = Objects.requireNonNull(handler, "handler");
        // The trampoline also makes a direct executor safe: user code never runs in JNI dispatch.
        this.dispatchQueue = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(maxPendingRequests), task -> {
                Thread thread = new Thread(task, "ice-admission-dispatch");
                thread.setDaemon(true);
                return thread;
            });
        LibDataChannel.initialize();
        synchronized (this) {
            handle = openNative(Objects.requireNonNull(bindAddress, "bindAddress").getHostAddress(), port,
                maxPendingRequests, requestTimeoutMillis);
            if (handle == 0) {
                dispatchQueue.shutdownNow();
                throw new IllegalStateException("Cannot acquire ICE UDP mux endpoint");
            }
            listenerId = listenerIdNative(handle);
        }
    }

    // JNI only copies these strings. Native code owns the packet and coalesces duplicates.
    @JNIAccess
    private boolean dispatch(long id, String localUfrag, String remoteUfrag, String address, int port) {
        if (requests.size() >= maxPendingRequests) return false;
        Request request = new Request(id, localUfrag, remoteUfrag, address, port);
        if (requests.putIfAbsent(id, request) != null) return true;
        try {
            request.timeout = DEADLINES.schedule(() -> cancel(request,
                new TimeoutException("Incoming ICE request expired")), requestTimeoutMillis, TimeUnit.MILLISECONDS);
            dispatchQueue.execute(() -> execute(request, () -> decide(request)));
            return true;
        } catch (Throwable error) {
            requests.remove(id, request);
            if (request.timeout != null) request.timeout.cancel(false);
            complete(request, null, error);
            return false;
        }
    }

    private void execute(Request request, Runnable task) {
        try { executor.execute(task); }
        catch (Throwable error) { cancel(request, error); }
    }

    private void decide(Request request) {
        if (!requests.containsKey(request.id)) return;
        try {
            CompletionStage<Acceptance> decision = Objects.requireNonNull(handler.onRequest(request), "decision stage");
            decision.whenComplete((settings, error) -> {
                if (error != null || settings == null)
                    cancel(request, error != null ? error : new CancellationException("Incoming ICE request rejected"));
                else execute(request, () -> finish(request, settings, null));
            });
        } catch (Throwable error) { cancel(request, error); }
    }

    private synchronized int openListenerId() {
        if (handle == 0) throw new CancellationException("ICE listener closed");
        return listenerId;
    }

    private static void complete(Request request, @Nullable PeerConnection peer, @Nullable Throwable error) {
        // Removing the slot is synchronous. Application continuations use a separate
        // completion worker and cannot block the deadline or JNI dispatch thread.
        CompletableFuture.runAsync(() -> {
            if (error == null) request.completion.complete(peer);
            else request.completion.completeExceptionally(error);
        });
    }

    private void cancel(Request request, Throwable cause) {
        request.cancellation.compareAndSet(null, cause);
        if (!request.settling.compareAndSet(false, true)) return;
        if (request.timeout != null) request.timeout.cancel(false);
        int id;
        synchronized (this) { id = handle == 0 ? -1 : listenerId; }
        if (id >= 0) rejectNative(id, request.id);
        requests.remove(request.id, request);
        complete(request, null, cause);
    }

    private static void checkCancellation(Request request) {
        Throwable cause = request.cancellation.get();
        if (cause != null) throw new CompletionException(cause);
    }

    private void finish(Request request, @Nullable Acceptance settings, @Nullable Throwable error) {
        if (!request.settling.compareAndSet(false, true)) return;
        PeerConnection peer = null;
        int preparedHandle = -1;
        try {
            int id = openListenerId();
            checkCancellation(request);
            if (error != null) throw new CompletionException(error);
            if (settings == null) throw new CancellationException("Incoming ICE request rejected");
            if (!Instant.now().isBefore(settings.expiresAt)) throw new TimeoutException("Admission settings expired");
            if (settings.existingPeer != null) {
                int result = attachNative(id, request.id, settings.existingPeer.peerHandle);
                if (result != 0) throw new IllegalStateException("Cannot attach incoming ICE tuple: " + result);
                if (request.timeout != null) request.timeout.cancel(false);
                requests.remove(request.id, request);
                complete(request, settings.existingPeer, null);
                return;
            }
            int[] prepared = prepareNative(id, request.id, settings.configuration, settings.remoteDescription,
                request.localUfrag, settings.localPassword,
                settings.certificate == null ? null : settings.certificate.toString(),
                settings.key == null ? null : settings.key.toString(), settings.keyPassword);
            preparedHandle = prepared[1];
            if (preparedHandle >= 0) peer = PeerConnection.fromNative(preparedHandle, settings.peerExecutor);
            if (prepared[0] != 0) throw new IllegalStateException("Cannot prepare incoming ICE peer: " + prepared[0]);
            if (peer == null) throw new IllegalStateException("Native prepare returned no peer");
            peer.installNativeListener();
            // Application code may close this listener or the peer. Never hold a listener lock here.
            settings.initializer.accept(peer);
            id = openListenerId();
            checkCancellation(request);
            if (!Instant.now().isBefore(settings.expiresAt)) throw new TimeoutException("Admission settings expired");
            if (peer.preparationCloseRequested()) throw new CancellationException("Incoming peer closed during setup");
            int result = acceptNative(id, request.id, peer.peerHandle);
            if (result != 0) throw new IllegalStateException("Cannot accept incoming ICE peer: " + result);
            if (!peer.releasePreparation()) throw new CancellationException("Incoming peer closed during acceptance");
            if (request.timeout != null) request.timeout.cancel(false);
            requests.remove(request.id, request);
            complete(request, peer, null);
            return;
        } catch (Throwable cause) {
            error = cause;
            int id;
            synchronized (this) { id = handle == 0 ? -1 : listenerId; }
            if (id >= 0) rejectNative(id, request.id);
        }
        if (request.timeout != null) request.timeout.cancel(false);
        if (preparedHandle < 0) {
            requests.remove(request.id, request);
            complete(request, null, error);
        } else cleanup(preparedHandle, peer, request, error);
    }

    private void cleanup(int preparedHandle, @Nullable PeerConnection peer, Request request, Throwable error) {
        if (peer != null) {
            peer.closeAsync().whenComplete((ignored, closeError) -> {
                if (closeError != null) { failure.set(closeError); return; }
                try {
                    peer.releasePreparation();
                    peer.close();
                    requests.remove(request.id, request);
                    complete(request, null, error);
                } catch (Throwable failureCause) { failure.set(failureCause); }
            });
            return;
        }
        // No wrapper could be constructed. Keep the raw handle until teardown succeeds.
        CLEANUP.execute(() -> {
            try {
                if (LibDataChannelNative.rtcClosePeerConnectionAndWait(preparedHandle, 5000) == 0) {
                    LibDataChannelNative.rtcDeletePeerConnection(preparedHandle);
                    requests.remove(request.id, request);
                    complete(request, null, error);
                    return;
                }
            } catch (Throwable closeError) { failure.set(closeError); }
            CLEANUP.schedule(() -> cleanup(preparedHandle, null, request, error), 100, TimeUnit.MILLISECONDS);
        });
    }

    /** An admission infrastructure failure, for diagnostics. */
    public @Nullable Throwable failure() { return failure.get(); }

    public synchronized Statistics statistics() {
        if (handle == 0) throw new IllegalStateException("ICE listener closed");
        return new Statistics(statsNative(listenerId));
    }

    /** @deprecated Use {@link #statistics()} for named counters. */
    @Deprecated
    public synchronized long[] stats() {
        if (handle == 0) throw new IllegalStateException("ICE listener closed");
        return statsNative(listenerId);
    }

    @Override
    public void close() {
        synchronized (this) {
            if (handle == 0) return;
            long closing = handle;
            handle = 0;
            try { closeNative(closing); }
            catch (Throwable error) { handle = closing; throw error; }
        }
        // A direct executor may be running user code on this thread. Closing the
        // listener cancels its request; it must not interrupt that application code.
        dispatchQueue.getQueue().clear();
        dispatchQueue.shutdown();
        for (Request request : requests.values())
            cancel(request, new CancellationException("ICE listener closed"));
    }

    private native long openNative(String address, int port, int maxPendingRequests, int requestTimeoutMillis);
    private static native void closeNative(long handle);
    private static int[] prepareNative(int handle, long requestId, PeerConnectionConfiguration config,
        String remoteDescription, String localUfrag, String localPassword,
        @Nullable String certificate, @Nullable String key, @Nullable String keyPassword) {
        return prepareConfiguredNative(handle, requestId, PeerConnection.iceUrisToStrings(config.iceServers),
            config.proxyServer == null ? null : config.proxyServer.toASCIIString(),
            config.bindAddress == null ? null : config.bindAddress.getHostAddress(),
            config.certificateType.state, config.iceTransportPolicy.state, config.enableIceTcp,
            config.enableIceUdpMux, config.disableAutoNegotiation, config.forceMediaTransport,
            config.portRangeBegin, config.portRangeEnd, config.mtu, config.maxMessageSize,
            certificate, key, keyPassword, remoteDescription, localUfrag, localPassword);
    }
    private static native int[] prepareConfiguredNative(int handle, long requestId,
        String @Nullable [] iceServers, @Nullable String proxyServer, @Nullable String bindAddress,
        int certificateType, int iceTransportPolicy, boolean enableIceTcp, boolean enableIceUdpMux,
        boolean disableAutoNegotiation, boolean forceMediaTransport, short portRangeBegin, short portRangeEnd,
        int mtu, int maxMessageSize, @Nullable String certificate, @Nullable String key, @Nullable String keyPassword,
        String remoteDescription, String localUfrag, String localPassword);
    private static native int acceptNative(int handle, long requestId, int peer);
    private static native int attachNative(int handle, long requestId, int peer);
    private static native int rejectNative(int handle, long requestId);
    private static native long[] statsNative(int handle);
    private static native int listenerIdNative(long handle);
}
