package tel.schich.libdatachannel;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;

/** Test-owned admission; verifies real transport budgeting, not a diagnostic authorization policy. */
public final class NativeUdpSendLimitsProbe {
    static void check(boolean ok, String message) { NativeTransportProbe.check(ok, message); }
    static void await(BooleanSupplier condition, String message) throws Exception { NativeTransportProbe.await(condition, message); }
    static int port(InetAddress bind) throws Exception {
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(bind, 0))) { return socket.getLocalPort(); }
    }
    static PeerConnectionConfiguration config(InetAddress bind) {
        return PeerConnectionConfiguration.DEFAULT.withBindAddress(bind).withEnableIceUdpMux(true)
            .withDisableAutoNegotiation(true).withMtu(1248).withMaxMessageSize(262144);
    }
    static void send(DataChannel channel, int value) {
        ByteBuffer data = ByteBuffer.allocateDirect(32);
        data.putInt(value); while (data.hasRemaining()) data.put((byte)value); data.flip();
        channel.sendMessage(data);
    }
    static final class Pair implements AutoCloseable {
        final String ufrag = NativeDiagnosticProbe.randomCredential(), password = NativeDiagnosticProbe.randomCredential();
        final String clientUfrag = NativeDiagnosticProbe.randomCredential();
        final PeerConnection client;
        final DataChannel[] outbound = new DataChannel[2];
        final AtomicReferenceArray<DataChannel> inbound = new AtomicReferenceArray<>(2);
        final AtomicInteger opened = new AtomicInteger(), replies = new AtomicInteger();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final CompletableFuture<PeerConnection> accepted = new CompletableFuture<>();
        final boolean limited;
        final long deadline;
        final int count, size;
        Pair(InetAddress bind, int serverPort, boolean limited, int count, int size, long lifetime) throws Exception {
            this.limited = limited; this.count = count; this.size = size;
            this.deadline = UdpSendLimits.monotonicTimeMillis() + lifetime;
            int clientPort = port(bind);
            client = PeerConnection.createPeerWithUdpLimits(config(bind).withPortRangeBegin(clientPort).withPortRangeEnd(clientPort), Runnable::run, null,
                new UdpSendLimits(2048, 1200, UdpSendLimits.monotonicTimeMillis() + 15000,
                    new InetSocketAddress(bind, serverPort)));
            for (int i = 0; i < 2; ++i) {
                final int index = i;
                outbound[i] = client.createDataChannel("budget-" + i, DataChannelInitSettings.DEFAULT
                    .withReliability(DataChannelReliability.DEFAULT.withUnordered(i == 1).withUnreliable(i == 1).withMaxRetransmits(0)));
                outbound[i].onOpen.register(dc -> opened.incrementAndGet());
                outbound[i].onMessage.register(DataChannelCallback.Message.handleBinary((dc, data) -> {
                    if (data.remaining() != 32) { failure.compareAndSet(null, new AssertionError("bounded echo")); return; }
                    if (data.getInt() == index + 1) replies.incrementAndGet();
                }));
            }
            client.setLocalDescription("offer", clientUfrag, NativeDiagnosticProbe.randomCredential());
        }
        IceUdpMuxListener.Acceptance accept(IceUdpMuxListener.Request request, DtlsIdentity identity, InetAddress bind) throws Exception {
            check(request.remoteUfrag().equals(clientUfrag), "test-owned request association");
            request.completion().whenComplete((peer, error) -> {
                if (error != null) accepted.completeExceptionally(error); else accepted.complete(peer);
            });
            var builder = IceUdpMuxListener.Acceptance.builder(client.localDescription(), password)
                .configuration(config(bind)).identity(identity).expiresAt(Instant.now().plusSeconds(5)).initialize(peer -> {
                    peer.onDataChannel.register((p, dc) -> {
                        int index = dc.label().equals("budget-0") ? 0 : dc.label().equals("budget-1") ? 1 : -1;
                        if (index < 0 || !inbound.compareAndSet(index, null, dc)) { failure.compareAndSet(null, new AssertionError("exact channels")); return; }
                        DataChannelReliability reliability = dc.reliability();
                        if (reliability.isUnreliable() != (index == 1) || reliability.isUnordered() != (index == 1) || reliability.maxRetransmits() != 0)
                            failure.compareAndSet(null, new AssertionError("exact negotiated reliability"));
                        dc.onMessage.register(DataChannelCallback.Message.handleBinary((channel, bytes) -> {
                            if (bytes.remaining() != 32) { failure.compareAndSet(null, new AssertionError("bounded input")); return; }
                            send(channel, bytes.getInt());
                        }));
                    });
                });
            if (limited) builder.udpSendLimits(new UdpSendLimits(count, size, deadline,
                new InetSocketAddress(InetAddress.getByName(request.remoteAddress()), request.remotePort())));
            return builder.build();
        }
        PeerConnection start(String address, int port, String fingerprint) throws Exception {
            client.setRemoteDescription(NativeDiagnosticProbe.answer(address, port, ufrag, password, fingerprint), SessionDescriptionType.ANSWER);
            return accepted.get(5, TimeUnit.SECONDS);
        }
        void ready() throws Exception { await(() -> opened.get() == 2 && inbound.get(0) != null && inbound.get(1) != null, "both real channels open"); }
        void ping() throws Exception {
            int before = replies.get(); send(outbound[0], 1); send(outbound[1], 2);
            await(() -> replies.get() == before + 2, "reliable and unreliable round trips");
            check(failure.get() == null, "channel failure: " + failure.get());
        }
        public void close() throws Exception {
            PeerConnection host = accepted.isCompletedExceptionally() ? null : accepted.getNow(null);
            if (host != null) check(host.closeAndAwait(Duration.ofSeconds(5)), "host cleanup");
            check(client.closeAndAwait(Duration.ofSeconds(5)), "client cleanup");
        }
    }
    static void transport(Path cert, Path key, String address, String mode) throws Exception {
        InetAddress bind = InetAddress.getByName(address); int port = port(bind);
        DtlsIdentity identity = new DtlsIdentity(cert, key);
        Map<String, Pair> peers = new ConcurrentHashMap<>();
        try (IceUdpMuxListener mux = new IceUdpMuxListener(bind, port, Runnable::run, request -> {
                Pair pair = peers.get(request.localUfrag());
                return CompletableFuture.completedFuture(pair == null ? null : pair.accept(request, identity, bind));
             });
             Pair bounded = new Pair(bind, port, true, mode.equals("count-before-dtls") ? 1 : 256,
                 mode.equals("size-before-dtls") ? 1 : 1200, mode.equals("expiry") ? 1500 : 12000);
             Pair ordinary = new Pair(bind, port, false, 0, 0, 12000)) {
            peers.put(bounded.ufrag, bounded); peers.put(ordinary.ufrag, ordinary);
            String fingerprint = NativeDiagnosticProbe.fingerprint(cert);
            PeerConnection host = bounded.start(address, port, fingerprint);
            if (mode.endsWith("before-dtls")) {
                await(() -> host.udpSendStats().orElseThrow().rejectedDatagrams() > 0, "native handshake sends rejected");
                check(bounded.opened.get() == 0, "no DTLS/data channels within insufficient budget");
                UdpSendStats stats = host.udpSendStats().orElseThrow();
                check(stats.sentDatagrams() <= (mode.startsWith("size") ? 0 : 1), "actual OS send cap");
                check(stats.lastRejection() == (mode.startsWith("size") ? UdpSendStats.Rejection.SIZE : UdpSendStats.Rejection.COUNT), "exact denial cause");
            } else {
                bounded.ready(); bounded.ping();
                UdpSendStats established = host.udpSendStats().orElseThrow();
                check(established.sentDatagrams() > 2 && established.sentBytes() > 1000 && established.rejectedDatagrams() == 0,
                    "actual ICE/DTLS/SCTP sends counted with MTU1248");
                PeerConnection unlimited = ordinary.start(address, port, fingerprint); ordinary.ready(); ordinary.ping();
                check(unlimited.udpSendStats().isEmpty() && mux.statistics().agents() == 2, "same mux includes unlimited peer");
                if (mode.equals("expiry")) {
                    while (UdpSendLimits.monotonicTimeMillis() <= bounded.deadline + 5) Thread.sleep(5);
                    long before = host.udpSendStats().orElseThrow().sentDatagrams();
                    send(bounded.inbound.get(1), 9);
                    await(() -> host.udpSendStats().orElseThrow().lastRejection() == UdpSendStats.Rejection.EXPIRED, "fixed native expiry rejects application send");
                    check(host.udpSendStats().orElseThrow().sentDatagrams() == before, "nothing sent after expiry");
                } else {
                    for (int i = 0; i < 1000 && host.udpSendStats().orElseThrow().rejectedDatagrams() == 0; ++i) send(bounded.inbound.get(1), 9);
                    await(() -> host.udpSendStats().orElseThrow().lastRejection() == UdpSendStats.Rejection.COUNT, "application traffic exhausts actual native send cap");
                    check(host.udpSendStats().orElseThrow().reservedDatagrams() == 256 && host.udpSendStats().orElseThrow().sentDatagrams() == 256, "immutable count exactly256");
                }
                ordinary.ping(); // Existing transport still communicates after another agent exhausts its budget.
                check(bounded.client.udpSendStats().orElseThrow().sentDatagrams() > 0, "outgoing JNI constructor installs budget too");
            }
        }
        try (DatagramSocket rebound = new DatagramSocket(new InetSocketAddress(bind, port))) { check(rebound.isBound(), "shared socket released"); }
        System.out.println("native-udp-limits PASS family=" + address + " mode=" + mode + " admission=test-owned gameplay=false");
    }
    static void reuse(Path cert, Path key) throws Exception {
        InetAddress bind = InetAddress.getByName("127.0.0.1"); int port = port(bind);
        AtomicReference<PeerConnection> accepted = new AtomicReference<>();
        ArrayBlockingQueue<IceUdpMuxListener.Request> requests = new ArrayBlockingQueue<>(4);
        try (PeerConnection client = NativeTransportProbe.client()) {
            client.createDataChannel("fixture"); client.setLocalDescription("offer", NativeTransportProbe.CLIENT_UFRAG, NativeTransportProbe.CLIENT_PASSWORD);
            long deadline = UdpSendLimits.monotonicTimeMillis() + 10000;
            try (IceUdpMuxListener mux = new IceUdpMuxListener(bind, port, Runnable::run, request -> {
                requests.add(request);
                return CompletableFuture.completedFuture(accepted.get() == null ? IceUdpMuxListener.Acceptance.builder(client.localDescription(), NativeTransportProbe.SERVER_PASSWORD)
                    .identity(new DtlsIdentity(cert, key)).udpSendLimits(new UdpSendLimits(1, 1200, deadline, null)).build() :
                    IceUdpMuxListener.Acceptance.reuse(accepted.get()));
            }); DatagramSocket first = new DatagramSocket(); DatagramSocket second = new DatagramSocket()) {
                byte[] packet = NativeTransportProbe.binding("budgetReuse", NativeTransportProbe.SERVER_PASSWORD);
                first.send(new DatagramPacket(packet, packet.length, bind, port));
                var initial = requests.poll(3, TimeUnit.SECONDS); check(initial != null, "first request");
                PeerConnection host = initial.completion().toCompletableFuture().get(3, TimeUnit.SECONDS); accepted.set(host);
                try {
                    await(() -> host.udpSendStats().orElseThrow().sentDatagrams() == 1, "initial budget used");
                    long constructions = PeerConnection.nativeCreationAttempts();
                    second.send(new DatagramPacket(packet, packet.length, bind, port));
                    var additional = requests.poll(3, TimeUnit.SECONDS); check(additional != null, "reuse request");
                    check(additional.completion().toCompletableFuture().get(3, TimeUnit.SECONDS) == host, "exact existing wrapper reused");
                    await(() -> host.udpSendStats().orElseThrow().rejectedDatagrams() > 0, "reuse has no fresh send allowance");
                    check(host.udpSendStats().orElseThrow().sentDatagrams() == 1 && PeerConnection.nativeCreationAttempts() == constructions, "same native agent retains immutable budget");
                } finally { check(host.closeAndAwait(Duration.ofSeconds(5)), "reused host cleanup"); }
                check(mux.statistics().agents() == 0 && mux.statistics().mappedTuples() == 0, "reused tuple cleanup");
            }
        }
        System.out.println("native-udp-limits PASS existingAgentReuse=retainsBudget");
    }
    public static void main(String[] args) throws Exception {
        Path cert = Path.of(args[0]), key = Path.of(args[1]);
        for (String address : new String[]{"127.0.0.1", "::1"})
            for (String mode : new String[]{"count", "expiry", "count-before-dtls", "size-before-dtls"}) transport(cert, key, address, mode);
        reuse(cert, key);
    }
}
