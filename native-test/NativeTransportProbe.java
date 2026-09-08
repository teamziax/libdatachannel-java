package tel.schich.libdatachannel;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Real UDP regression for asynchronous ICE acceptance and authenticated DTLS. */
public final class NativeTransportProbe {
    static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
    static final int PORT = 49184;
    static final String CLIENT_UFRAG = "clientFixtureUf", CLIENT_PASSWORD = "p".repeat(24);
    static final String SERVER_PASSWORD = "fixedTestPassword0000000000000000";
    static String field(String sdp, String name) {
        return sdp.lines().filter(x -> x.startsWith("a=" + name + ":")).findFirst().orElseThrow()
            .substring(name.length() + 3).trim();
    }
    static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    static void await(java.util.function.BooleanSupplier condition, String message) throws Exception {
        for (int i = 0; i < 400 && !condition.getAsBoolean(); i++) Thread.sleep(5);
        check(condition.getAsBoolean(), message);
    }
    static PeerConnection client() {
        return PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withDisableAutoNegotiation(true).withBindAddress(LOOPBACK));
    }
    static IceUdpMuxListener.Acceptance settings(Path certificate, Path key, String offer,
            java.util.function.Consumer<PeerConnection> initializer) {
        return IceUdpMuxListener.Acceptance.builder(offer, SERVER_PASSWORD)
            .identity(new DtlsIdentity(certificate, key)).initialize(initializer).build();
    }
    static String answer(String ufrag, String fingerprint) {
        return "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n" +
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\na=setup:active\r\n" +
            "a=ice-ufrag:" + ufrag + "\r\na=ice-pwd:" + SERVER_PASSWORD + "\r\na=fingerprint:sha-256 " + fingerprint +
            "\r\na=sctp-port:5000\r\na=max-message-size:262144\r\na=candidate:1 1 UDP 2130706431 127.0.0.1 " + PORT +
            " typ host\r\na=end-of-candidates\r\n";
    }
    public static void main(String[] args) throws Exception {
        Path certificate = Path.of(args[0]), key = Path.of(args[1]);
        byte[] der;
        try (var input = Files.newInputStream(certificate)) {
            der = CertificateFactory.getInstance("X.509").generateCertificate(input).getEncoded();
        }
        String fingerprint = HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
        try (PeerConnection encrypted = PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withDisableAutoNegotiation(true),
                Runnable::run, certificate, Path.of(args[2]), "test-only-password")) {
            encrypted.createDataChannel("encrypted-key");
            encrypted.setLocalDescription(null, "encryptedIdentity", "publicTestPassword0000000");
            check(field(encrypted.localDescription(), "fingerprint").equals("sha-256 " + fingerprint), "encrypted key preserves identity");
            check(encrypted.closeAndAwait(Duration.ofSeconds(5)), "encrypted-key peer cleanup");
        }
        firstRequest(certificate, key, false);
        firstRequest(certificate, key, true);
        cancelledRequests(certificate, key);
        stalledExecutorCancellation();
        reusedPeer(certificate, key);
        failedDecisions(certificate, key);
        closeDuringInitialization(certificate, key);
        for (int length : new int[] {167, 178, 256}) run(certificate, key, fingerprint, length, false);
        run(certificate, key, fingerprint, 167, true);
    }

    static byte[] binding(String localUfrag, String password) throws Exception {
        byte[] username = (localUfrag + ":" + CLIENT_UFRAG).getBytes(StandardCharsets.US_ASCII);
        ByteBuffer packet = ByteBuffer.allocate(2048);
        packet.putShort((short) 1).putShort((short) 0).putInt(0x2112a442);
        packet.putInt(0x12345678).putLong(0x0102030405060708L);
        packet.putShort((short) 6).putShort((short) username.length).put(username);
        while (packet.position() % 4 != 0) packet.put((byte) 0);
        packet.putShort((short) 0x24).putShort((short) 4).putInt(2130706431);
        packet.putShort((short) 0x802a).putShort((short) 8).putLong(0x7071727374757677L);
        packet.putShort((short) 0x25).putShort((short) 0);
        int integrity = packet.position();
        packet.putShort(2, (short) (integrity + 24 - 20));
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(password.getBytes(StandardCharsets.US_ASCII), "HmacSHA1"));
        byte[] digest = mac.doFinal(Arrays.copyOf(packet.array(), integrity));
        packet.putShort((short) 8).putShort((short) 20).put(digest);
        return Arrays.copyOf(packet.array(), packet.position());
    }

    static void firstRequest(Path certificate, Path key, boolean forged) throws Exception {
        String ufrag = "singleRequestServer";
        CompletableFuture<IceUdpMuxListener.Acceptance> decision = new CompletableFuture<>();
        ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(2);
        AtomicInteger notifications = new AtomicInteger();
        try (PeerConnection client = client();
             IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, Runnable::run, request -> {
                 notifications.incrementAndGet(); arrivals.add(request); return decision;
             }); DatagramSocket sender = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0))) {
            client.createDataChannel("fixture");
            client.setLocalDescription("offer", CLIENT_UFRAG, CLIENT_PASSWORD);
            long before = PeerConnection.nativeCreationAttempts();
            byte[] packet = binding(ufrag, forged ? "wrongPassword0000000000000" : SERVER_PASSWORD);
            sender.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT)); // Exactly one transmission.
            IceUdpMuxListener.Request request = arrivals.poll(5, TimeUnit.SECONDS);
            check(request != null, "initial request reaches asynchronous listener");
            check(request.localUfrag().equals(ufrag) && request.remoteUfrag().equals(CLIENT_UFRAG), "parsed request metadata");
            Thread.sleep(150);
            check(PeerConnection.nativeCreationAttempts() == before && mux.statistics().agents() == 0, "no peer before decision");
            decision.complete(settings(certificate, key, client.localDescription(), peer -> {}));
            if (forged) {
                try { request.completion().toCompletableFuture().get(5, TimeUnit.SECONDS); throw new AssertionError("forged STUN accepted"); }
                catch (ExecutionException expected) { /* Native integrity verification rejected it. */ }
                check(PeerConnection.nativeCreationAttempts() == before && mux.statistics().agents() == 0 && mux.statistics().mappedTuples() == 0,
                    "forged integrity creates no peer or mapping");
                check(mux.failure() == null, "ordinary rejection keeps listener healthy");
                System.out.println("native-transport PASS forgedIntegrity=no-peer");
            } else {
                PeerConnection host = request.completion().toCompletableFuture().get(5, TimeUnit.SECONDS);
                try {
                    sender.setSoTimeout(3000);
                    boolean response = false;
                    for (int i = 0; i < 20 && !response; i++) {
                        DatagramPacket received = new DatagramPacket(new byte[2048], 2048);
                        sender.receive(received);
                        ByteBuffer data = ByteBuffer.wrap(received.getData(), 0, received.getLength());
                        response = received.getLength() >= 20 && data.getShort(0) == 0x0101 &&
                            data.getInt(8) == 0x12345678 && data.getLong(12) == 0x0102030405060708L;
                    }
                    check(response && notifications.get() == 1, "retained first request receives response without retransmission");
                    System.out.println("native-transport PASS firstRequestSent=1 delayedAcceptance=true response=true");
                } finally { check(host.closeAndAwait(Duration.ofSeconds(5)), "single-request cleanup"); }
            }
        }
    }

    static void cancelledRequests(Path certificate, Path key) throws Exception {
        for (boolean close : new boolean[] {false, true}) {
            CompletableFuture<IceUdpMuxListener.Acceptance> decision = new CompletableFuture<>();
            ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(1);
            try (PeerConnection client = client();
                 IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, 1, Duration.ofMillis(200), Runnable::run,
                     request -> { arrivals.add(request); return decision; });
                 DatagramSocket sender = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0))) {
                client.createDataChannel("fixture"); client.setLocalDescription("offer", CLIENT_UFRAG, CLIENT_PASSWORD);
                long before = PeerConnection.nativeCreationAttempts();
                byte[] packet = binding("cancelledServer", SERVER_PASSWORD);
                sender.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
                IceUdpMuxListener.Request request = arrivals.poll(5, TimeUnit.SECONDS);
                check(request != null, "pending cancellation fixture");
                if (close) mux.close();
                try { request.completion().toCompletableFuture().get(5, TimeUnit.SECONDS); throw new AssertionError("cancelled request accepted"); }
                catch (ExecutionException | CancellationException expected) { }
                decision.complete(settings(certificate, key, client.localDescription(), peer -> { throw new AssertionError("late initializer"); }));
                Thread.sleep(50);
                check(PeerConnection.nativeCreationAttempts() == before, "late decision cannot create a peer");
            }
        }
        System.out.println("native-transport PASS timeoutAndClose=cancelled lateDecisions=no-peer");
    }

    static void stalledExecutorCancellation() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CountDownLatch blocked = new CountDownLatch(1), release = new CountDownLatch(1);
        ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(1);
        AtomicInteger handlers = new AtomicInteger();
        try (IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, 1, Duration.ofMillis(300), executor,
                request -> { handlers.incrementAndGet(); arrivals.add(request); return new CompletableFuture<>(); });
             DatagramSocket sender = new DatagramSocket()) {
            byte[] packet = binding("executorDeadline", SERVER_PASSWORD);
            sender.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
            var request = arrivals.poll(3, TimeUnit.SECONDS);
            check(request != null, "executor fixture receives first request");
            executor.execute(() -> {
                blocked.countDown();
                try { release.await(); } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            });
            check(blocked.await(3, TimeUnit.SECONDS), "application executor stalled");
            try { request.completion().toCompletableFuture().get(3, TimeUnit.SECONDS); throw new AssertionError("timeout accepted"); }
            catch (ExecutionException expected) { }
            check(mux.statistics().pendingRequests() == 0, "native timeout finished independently");
            byte[] second = binding("secondExecutorDeadline", SERVER_PASSWORD);
            sender.send(new DatagramPacket(second, second.length, LOOPBACK, PORT));
            await(() -> mux.statistics().notifications() == 2, "second notification reaches Java");
            check(mux.statistics().pendingRequests() == 1, "Java timeout freed its admission slot before executor resumed");
            mux.close();
            release.countDown();
            executor.shutdown();
            check(executor.awaitTermination(3, TimeUnit.SECONDS), "executor drains cancelled work");
            check(handlers.get() == 1, "late queued handler cannot revive a closed request");
        } finally { release.countDown(); executor.shutdownNow(); }
        System.out.println("native-transport PASS stalledExecutorTimeout=settled pendingSlot=reusable");
    }

    static void reusedPeer(Path certificate, Path key) throws Exception {
        AtomicReference<PeerConnection> accepted = new AtomicReference<>();
        ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(4);
        try (PeerConnection client = client()) {
            client.createDataChannel("fixture"); client.setLocalDescription("offer", CLIENT_UFRAG, CLIENT_PASSWORD);
            try (IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, Runnable::run, request -> {
                arrivals.add(request);
                return CompletableFuture.completedFuture(accepted.get() == null ?
                    settings(certificate, key, client.localDescription(), peer -> {}) : IceUdpMuxListener.Acceptance.reuse(accepted.get()));
            }); DatagramSocket first = new DatagramSocket(); DatagramSocket second = new DatagramSocket(); DatagramSocket forged = new DatagramSocket()) {
                byte[] packet = binding("reuseExistingPeer", SERVER_PASSWORD);
                first.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
                var request = arrivals.poll(3, TimeUnit.SECONDS); check(request != null, "new peer notification");
                var peer = request.completion().toCompletableFuture().get(3, TimeUnit.SECONDS);
                accepted.set(peer);
                try {
                    await(() -> mux.statistics().mappedTuples() == 1, "first tuple attached");
                    long constructions = PeerConnection.nativeCreationAttempts();
                    second.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
                    var additional = arrivals.poll(3, TimeUnit.SECONDS); check(additional != null, "additional tuple notification");
                    check(additional.completion().toCompletableFuture().get(3, TimeUnit.SECONDS) == peer, "reuse returns the same Java wrapper");
                    await(() -> mux.statistics().mappedTuples() == 2, "second authenticated tuple attached");
                    check(mux.statistics().agents() == 1 && PeerConnection.nativeCreationAttempts() == constructions,
                        "additional tuple does not allocate a peer");
                    byte[] invalid = binding("reuseExistingPeer", "incorrectPassword000000000");
                    forged.send(new DatagramPacket(invalid, invalid.length, LOOPBACK, PORT));
                    var bad = arrivals.poll(3, TimeUnit.SECONDS); check(bad != null, "forged tuple notification");
                    try { bad.completion().toCompletableFuture().get(3, TimeUnit.SECONDS); throw new AssertionError("forged reuse accepted"); }
                    catch (ExecutionException expected) { }
                    check(mux.statistics().agents() == 1 && mux.statistics().mappedTuples() == 2,
                        "rejected tuple leaves caller-owned peer alive");
                    peer.closeAsync().toCompletableFuture().get(5, TimeUnit.SECONDS);
                    check(mux.statistics().agents() == 0, "asynchronous close confirms resource destruction");
                } finally { peer.closeAndAwait(Duration.ofSeconds(5)); }
            }
        }
        System.out.println("native-transport PASS existingPeerReuse=authenticated forgedReuse=preservesPeer asyncClose=complete");
    }

    static void failedDecisions(Path certificate, Path key) throws Exception {
        for (String failureKind : new String[] {"handler", "initializer", "closedPeer", "configuration", "expired"}) {
            ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(1);
            AtomicReference<PeerConnection> initialized = new AtomicReference<>();
            try (PeerConnection client = client()) {
                client.createDataChannel("fixture"); client.setLocalDescription("offer", CLIENT_UFRAG, CLIENT_PASSWORD);
                String offer = client.localDescription();
                if (failureKind.equals("configuration")) offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" +
                    "a=ice-ufrag:" + CLIENT_UFRAG + "\r\na=ice-pwd:" + CLIENT_PASSWORD + "\r\na=fingerprint:" +
                    field(offer, "fingerprint") + "\r\na=setup:actpass\r\n"; // Credentials, but no media section.
                final String remoteOffer = offer;
                try (IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, Runnable::run, request -> {
                    arrivals.add(request);
                    if (failureKind.equals("handler")) throw new IllegalStateException("fixture handler failure");
                    return CompletableFuture.completedFuture(new IceUdpMuxListener.Acceptance(
                        PeerConnectionConfiguration.DEFAULT, remoteOffer, SERVER_PASSWORD, certificate, key, null,
                        Runnable::run, peer -> {
                            initialized.set(peer);
                            if (failureKind.equals("closedPeer")) peer.close();
                            throw new IllegalStateException("fixture initializer failure");
                        },
                        failureKind.equals("expired") ? java.time.Instant.EPOCH : java.time.Instant.MAX));
                }); DatagramSocket sender = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0))) {
                    long before = PeerConnection.nativeCreationAttempts();
                    byte[] packet = binding("failureFixtureServer", SERVER_PASSWORD);
                    sender.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
                    IceUdpMuxListener.Request request = arrivals.poll(5, TimeUnit.SECONDS);
                    check(request != null, "failure fixture metadata");
                    try { request.completion().toCompletableFuture().get(10, TimeUnit.SECONDS); throw new AssertionError("failed decision accepted"); }
                    catch (ExecutionException expected) { }
                    boolean allocated = failureKind.equals("initializer") || failureKind.equals("closedPeer") || failureKind.equals("configuration");
                    check(PeerConnection.nativeCreationAttempts() == before + (allocated ? 1 : 0), "creation ordering for " + failureKind);
                    check(mux.statistics().agents() == 0 && mux.statistics().mappedTuples() == 0 && mux.statistics().pendingRequests() == 0 && mux.failure() == null,
                        "failed decision frees native resources and leaves listener healthy: " + failureKind);
                    if (initialized.get() != null) check(initialized.get().closeAndAwait(Duration.ofMillis(1)), "binding cleanup was completed and is idempotent");
                }
            }
        }
        AtomicInteger handlers = new AtomicInteger();
        try (IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT,
                task -> { throw new RejectedExecutionException("fixture full executor"); },
                request -> { handlers.incrementAndGet(); return CompletableFuture.completedFuture(null); });
             DatagramSocket sender = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0))) {
            long before = PeerConnection.nativeCreationAttempts();
            byte[] packet = binding("rejectedExecutor", SERVER_PASSWORD);
            sender.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
            await(() -> mux.statistics().notifications() == 1 && mux.statistics().pendingRequests() == 0, "executor rejection removes pending request");
            check(handlers.get() == 0 && PeerConnection.nativeCreationAttempts() == before && mux.failure() == null,
                "executor overload rejects without invoking handler or poisoning listener");
        }
        System.out.println("native-transport PASS handlerFailure=true initializerFailure=cleaned closedInitializerPeer=cleaned configurationFailure=cleaned expiry=no-peer executorRejection=no-peer");
    }

    static void closeDuringInitialization(Path certificate, Path key) throws Exception {
        AtomicReference<IceUdpMuxListener> listener = new AtomicReference<>();
        AtomicReference<PeerConnection> prepared = new AtomicReference<>();
        AtomicBoolean closeFinishedInsideInitializer = new AtomicBoolean();
        ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(1);
        try (PeerConnection client = client()) {
            client.createDataChannel("fixture"); client.setLocalDescription("offer", CLIENT_UFRAG, CLIENT_PASSWORD);
            try (IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, Runnable::run, request -> {
                arrivals.add(request);
                return CompletableFuture.completedFuture(settings(certificate, key, client.localDescription(), peer -> {
                    prepared.set(peer);
                    peer.onStateChange.register((p, state) -> {
                        if (state == PeerState.RTC_CLOSED) listener.get().close();
                    });
                    try {
                        CompletableFuture.runAsync(() -> listener.get().close()).get(3, TimeUnit.SECONDS);
                        closeFinishedInsideInitializer.set(true);
                    } catch (Exception error) { throw new CompletionException(error); }
                }));
            }); DatagramSocket sender = new DatagramSocket(new InetSocketAddress(LOOPBACK, 0))) {
                listener.set(mux);
                byte[] packet = binding("closeDuringSetup", SERVER_PASSWORD);
                sender.send(new DatagramPacket(packet, packet.length, LOOPBACK, PORT));
                IceUdpMuxListener.Request request = arrivals.poll(5, TimeUnit.SECONDS);
                check(request != null, "concurrent-close fixture metadata");
                try { request.completion().toCompletableFuture().get(8, TimeUnit.SECONDS); throw new AssertionError("closed listener accepted"); }
                catch (ExecutionException expected) { }
                check(closeFinishedInsideInitializer.get(), "initializer can wait for concurrent listener close without deadlocking");
                check(prepared.get() != null && prepared.get().closeAndAwait(Duration.ofMillis(1)), "concurrent close cleans the prepared peer");
            }
        }
        System.out.println("native-transport PASS initializerConcurrentClose=no-deadlock preparedPeer=cleaned");
    }

    static void run(Path certificate, Path key, String fingerprint, int ufragLength, boolean wrongFingerprint) throws Exception {
        String serverUfrag = "s".repeat(ufragLength);
        CompletableFuture<IceUdpMuxListener.Acceptance> decision = new CompletableFuture<>();
        ArrayBlockingQueue<IceUdpMuxListener.Request> arrivals = new ArrayBlockingQueue<>(4);
        AtomicInteger notifications = new AtomicInteger(), channelMask = new AtomicInteger(), callbackGuards = new AtomicInteger();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch opened = new CountDownLatch(2), messages = new CountDownLatch(402), failed = new CountDownLatch(1);
        PeerConnection host = null;
        try (IceUdpMuxListener mux = new IceUdpMuxListener(LOOPBACK, PORT, Runnable::run, request -> {
                notifications.incrementAndGet(); arrivals.add(request); return decision;
             }); PeerConnection client = client()) {
            long before = PeerConnection.nativeCreationAttempts();
            try (DatagramSocket noise = new DatagramSocket()) {
                byte[] garbage = new byte[40]; noise.send(new DatagramPacket(garbage, garbage.length, LOOPBACK, PORT));
                await(() -> mux.statistics().received() > 0, "native receives garbage");
                check(notifications.get() == 0 && mux.statistics().agents() == 0 && mux.statistics().mappedTuples() == 0, "garbage stays native and creates no state");
            }
            for (int channel = 0; channel < 2; channel++) {
                String label = channel == 0 ? "ordered" : "unordered";
                var init = DataChannelInitSettings.DEFAULT.withReliability(new DataChannelReliability(channel == 1, false, 0, 0));
                DataChannel dc = client.createDataChannel(label, init);
                dc.onOpen.register(d -> {
                    try { client.closeAndAwait(Duration.ofMillis(1)); failure.set(new AssertionError("callback teardown wait allowed")); }
                    catch (IllegalStateException expected) { callbackGuards.incrementAndGet(); }
                    opened.countDown();
                    for (int i = 0; i < 201; i++) {
                        ByteBuffer message = ByteBuffer.allocateDirect(2);
                        message.put((byte) 0).put((byte) (label.equals("ordered") ? 1 : 2)).flip(); d.sendMessage(message);
                    }
                });
            }
            client.setLocalDescription("offer", CLIENT_UFRAG, CLIENT_PASSWORD);
            client.setRemoteDescription(answer(serverUfrag, fingerprint), SessionDescriptionType.ANSWER);
            IceUdpMuxListener.Request request = arrivals.poll(10, TimeUnit.SECONDS);
            check(request != null, "STUN arrives before host peer exists");
            Thread.sleep(1100); // Force normal ICE retransmissions while application approval remains pending.
            check(notifications.get() == 1 && mux.statistics().duplicates() > 0 && mux.statistics().agents() == 0 &&
                PeerConnection.nativeCreationAttempts() == before, "duplicates coalesce before native peer creation");
            String offer = client.localDescription();
            if (wrongFingerprint) {
                String old = field(offer, "fingerprint"); char replacement = old.charAt(8) == '0' ? '1' : '0';
                offer = offer.replace(old, old.substring(0, 8) + replacement + old.substring(9));
            }
            decision.complete(settings(certificate, key, offer, peer -> {
                check(field(peer.localDescription(), "fingerprint").equals("sha-256 " + fingerprint), "published certificate identity");
                check(field(peer.localDescription(), "ice-ufrag").equals(serverUfrag), "explicit ICE username preserved");
                peer.onStateChange.register((p, state) -> { if (state == PeerState.RTC_FAILED) failed.countDown(); });
                peer.onDataChannel.register((p, dc) -> {
                    int bit = dc.label().equals("ordered") ? 1 : dc.label().equals("unordered") ? 2 : 0;
                    channelMask.getAndUpdate(mask -> mask | bit);
                    dc.onMessage.register(DataChannelCallback.Message.handleBinary((d, data) -> {
                        try { check(bit != 0 && data.remaining() == 2 && data.get() == 0 && data.get() == bit, "distinct channel payload"); messages.countDown(); }
                        catch (Throwable error) { failure.set(error); }
                    }));
                });
            }));
            host = request.completion().toCompletableFuture().get(5, TimeUnit.SECONDS);
            if (wrongFingerprint) {
                check(failed.await(15, TimeUnit.SECONDS), "DTLS rejects incorrect client fingerprint");
                check(opened.getCount() == 2 && channelMask.get() == 0, "wrong certificate opens no channels");
                System.out.println("native-transport PASS wrongRemoteFingerprint=dtls-rejected channels=0");
            } else {
                check(opened.await(10, TimeUnit.SECONDS) && messages.await(10, TimeUnit.SECONDS), "both channels deliver 402 messages");
                check(failure.get() == null && callbackGuards.get() == 2 && channelMask.get() == 3, "callback and data-channel checks");
                long[] stats = mux.stats();
                check(notifications.get() == 1 && stats[5] == 1 && stats[2] == 1 && stats[3] == 1 && stats[0] > 10,
                    "transport traffic stays native after one admission callback");
                System.out.println("native-transport PASS ufragChars=" + ufragLength + " admissionCallbacks=1 duplicates=" + stats[6] +
                    " datagrams=" + stats[0] + " channels=2 messages=402");
            }
        } finally { if (host != null) check(host.closeAndAwait(Duration.ofSeconds(5)), "accepted peer native cleanup"); }
    }
}
