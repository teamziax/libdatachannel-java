package tel.schich.libdatachannel;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Test-owned admission only: no provider authorization, game login or application promotion. */
public final class NativeDiagnosticProbe {
    static final SecureRandom RANDOM = new SecureRandom();
    static final String[] LABELS = {"diagnostic-reliable", "diagnostic-unreliable"};
    static final int FRAME_SIZE = 38, MAGIC = 0x44494147;

    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    static String randomCredential() {
        byte[] value = new byte[16]; RANDOM.nextBytes(value);
        return HexFormat.of().formatHex(value);
    }

    static String fingerprint(Path certificate) throws Exception {
        try (var input = Files.newInputStream(certificate)) {
            byte[] der = CertificateFactory.getInstance("X.509").generateCertificate(input).getEncoded();
            return HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
        }
    }

    static String wrongFingerprint(String value) {
        return (value.charAt(0) == '0' ? "1" : "0") + value.substring(1);
    }

    static String answer(String address, int port, String ufrag, String password, String fingerprint) {
        return "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n" +
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\na=setup:active\r\n" +
            "a=ice-ufrag:" + ufrag + "\r\na=ice-pwd:" + password + "\r\na=fingerprint:sha-256 " + fingerprint +
            "\r\na=sctp-port:5000\r\na=max-message-size:262144\r\na=candidate:1 1 UDP 2130706431 " + address + " " + port +
            " typ host\r\na=end-of-candidates\r\n";
    }

    static void install(DataChannel channel, int index, CountDownLatch roundTrips,
                        AtomicInteger opened, AtomicReference<Throwable> failure) {
        byte[] challenge = new byte[32]; RANDOM.nextBytes(challenge);
        AtomicBoolean started = new AtomicBoolean(), completed = new AtomicBoolean();
        AtomicInteger receivedFrames = new AtomicInteger();
        Runnable start = () -> {
            if (!started.compareAndSet(false, true)) return;
            try {
                DataChannelReliability actual = channel.reliability();
                check(channel.label().equals(LABELS[index]), "exact diagnostic channel label");
                check(actual.isUnordered() == (index == 1) && actual.isUnreliable() == (index == 1),
                    "negotiated reliability and ordering must match the requested channel");
                check(actual.maxRetransmits() == 0 && actual.maxPacketLifeTime().isZero(), "no retransmission budget on unreliable channel");
                opened.incrementAndGet();
                send(channel, index, 1, challenge);
            } catch (Throwable error) { failure.compareAndSet(null, error); }
        };
        channel.onMessage.register(DataChannelCallback.Message.handleBinary((dc, data) -> {
            try {
                check(receivedFrames.incrementAndGet() <= 2, "bounded one challenge and one reply per channel");
                check(data.remaining() == FRAME_SIZE && data.getInt() == MAGIC && data.get() == index, "bounded channel-specific challenge frame");
                int kind = data.get(); byte[] nonce = new byte[32]; data.get(nonce);
                if (kind == 1) send(dc, index, 2, nonce);
                else {
                    check(kind == 2 && Arrays.equals(nonce, challenge), "reply proves the independently generated local challenge");
                    if (completed.compareAndSet(false, true)) roundTrips.countDown();
                }
            } catch (Throwable error) { failure.compareAndSet(null, error); }
        }));
        channel.onOpen.register(dc -> start.run());
        if (channel.isOpen()) start.run();
    }

    static void send(DataChannel channel, int index, int kind, byte[] nonce) {
        ByteBuffer message = ByteBuffer.allocateDirect(FRAME_SIZE);
        message.putInt(MAGIC).put((byte)index).put((byte)kind).put(nonce).flip();
        channel.sendMessage(message);
    }

    static void run(Path certificate, Path key, String address, String invalidIdentity) throws Exception {
        InetAddress bind = InetAddress.getByName(address);
        int port;
        try (DatagramSocket reserve = new DatagramSocket(new InetSocketAddress(bind, 0))) { port = reserve.getLocalPort(); }
        String serverUfrag = randomCredential(), clientUfrag = randomCredential(), password = randomCredential();
        String fingerprint = fingerprint(certificate);
        AtomicInteger admissions = new AtomicInteger(), opened = new AtomicInteger();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch roundTrips = new CountDownLatch(4), failed = new CountDownLatch(1);
        CompletableFuture<PeerConnection> accepted = new CompletableFuture<>();
        AtomicReference<String> offer = new AtomicReference<>();
        PeerConnection host = null;
        try (PeerConnection client = PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT
                 .withDisableAutoNegotiation(true).withBindAddress(bind));
             IceUdpMuxListener listener = new IceUdpMuxListener(bind, port, Runnable::run, request -> {
                 admissions.incrementAndGet();
                 check(request.localUfrag().equals(serverUfrag) && request.remoteUfrag().equals(clientUfrag), "test-owned exact ICE credential admission");
                 request.completion().whenComplete((peer, error) -> {
                     if (error != null) accepted.completeExceptionally(error); else accepted.complete(peer);
                 });
                 return CompletableFuture.completedFuture(IceUdpMuxListener.Acceptance.builder(offer.get(), password)
                     .identity(new DtlsIdentity(certificate, key)).expiresAt(Instant.now().plusSeconds(5))
                     .initialize(peer -> {
                         check(NativeTransportProbe.field(peer.localDescription(), "fingerprint").equals("sha-256 " + fingerprint), "exact host DTLS identity");
                         peer.onStateChange.register((p, state) -> { if (state == PeerState.RTC_FAILED) failed.countDown(); });
                         peer.onDataChannel.register((p, channel) -> {
                             int index = Arrays.asList(LABELS).indexOf(channel.label());
                             if (index < 0) { failure.compareAndSet(null, new AssertionError("unexpected diagnostic channel")); return; }
                             install(channel, index, roundTrips, opened, failure);
                         });
                     }).build());
             })) {
            client.onStateChange.register((p, state) -> { if (state == PeerState.RTC_FAILED) failed.countDown(); });
            for (int i = 0; i < LABELS.length; ++i) {
                var reliability = DataChannelReliability.DEFAULT.withUnordered(i == 1).withUnreliable(i == 1).withMaxRetransmits(0);
                install(client.createDataChannel(LABELS[i], DataChannelInitSettings.DEFAULT.withReliability(reliability)), i, roundTrips, opened, failure);
            }
            client.setLocalDescription("offer", clientUfrag, randomCredential());
            String remoteOffer = client.localDescription();
            if (invalidIdentity.equals("client")) {
                String value = NativeTransportProbe.field(remoteOffer, "fingerprint").substring("sha-256 ".length());
                remoteOffer = remoteOffer.replace(value, wrongFingerprint(value));
            }
            offer.set(remoteOffer);
            check(listener.statistics().agents() == 0, "answer exists before any host peer admission");
            client.setRemoteDescription(answer(address, port, serverUfrag, password,
                invalidIdentity.equals("server") ? wrongFingerprint(fingerprint) : fingerprint), SessionDescriptionType.ANSWER);
            host = accepted.get(5, TimeUnit.SECONDS);
            if (invalidIdentity.isEmpty()) {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (roundTrips.getCount() > 0 && failure.get() == null && System.nanoTime() < deadline) Thread.sleep(5);
                check(failure.get() == null, "diagnostic callback failure: " + failure.get());
                check(roundTrips.getCount() == 0 && opened.get() == 4, "both directions prove independent random challenges on both channels");
                check(admissions.get() == 1 && listener.statistics().agents() == 1, "one admission and one transport peer");
                check(client.remoteAddress().getPort() == port, "actual selected mux port");
                check(InetAddress.getByName(host.localAddress().getHostString()).equals(bind), "actual selected local address family");
                CandidatePair pair = client.selectedCandidatePair();
                check(pair.remote().getPort() == port && InetAddress.getByName(pair.remote().getHostString()).equals(bind), "selected candidate SDP endpoint parsed");
                check(pair.localCandidate().orElseThrow().transport() == IceCandidate.Transport.UDP &&
                    pair.remoteCandidate().orElseThrow().type() == IceCandidate.Type.HOST, "actual selected UDP candidate type retained");
            } else {
                check(failed.await(10, TimeUnit.SECONDS), "incorrect pinned " + invalidIdentity + " identity must fail DTLS");
                check(opened.get() == 0 && roundTrips.getCount() == 4, "no diagnostic data before identity verification");
            }
            check(host.closeAndAwait(Duration.ofSeconds(5)), "host transport fully destroyed"); host = null;
            check(client.closeAndAwait(Duration.ofSeconds(5)), "client transport fully destroyed");
            check(listener.statistics().agents() == 0 && listener.statistics().mappedTuples() == 0 && listener.statistics().pendingRequests() == 0,
                "diagnostic peer state fully released");
        } finally { if (host != null) check(host.closeAndAwait(Duration.ofSeconds(5)), "failed diagnostic cleanup"); }
        try (DatagramSocket rebound = new DatagramSocket(new InetSocketAddress(bind, port))) { check(rebound.isBound(), "listener socket released"); }
        System.out.println("native-diagnostic PASS family=" + address + " invalidIdentity=" + (invalidIdentity.isEmpty() ? "none" : invalidIdentity) +
            " admission=test-owned channels=" + opened.get() + " independentRoundTrips=" + (4 - roundTrips.getCount()) + " gameplay=false");
    }

    public static void main(String[] args) throws Exception {
        Path certificate = Path.of(args[0]), key = Path.of(args[1]);
        run(certificate, key, "127.0.0.1", "");
        run(certificate, key, "::1", "");
        run(certificate, key, "127.0.0.1", "client");
        run(certificate, key, "127.0.0.1", "server");
    }
}
