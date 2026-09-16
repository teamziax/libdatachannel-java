package tel.schich.libdatachannel;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Same-machine libwebrtc interoperability fixture. Private test admission, never a public probe. */
public final class NativeMinecraftProfileHost {
    static final String[] LABELS = {"ReliableDataChannel", "UnreliableDataChannel"};
    static final int FRAME_SIZE = 39, MAGIC = 0x44494147;
    final AtomicReference<Throwable> failure = new AtomicReference<>();
    final AtomicInteger mask = new AtomicInteger(), opened = new AtomicInteger(), completed = new AtomicInteger();
    final AtomicBoolean closing = new AtomicBoolean(), ice = new AtomicBoolean();
    final AtomicReference<PeerConnection> peer = new AtomicReference<>();
    final AtomicReference<CompletableFuture<PeerConnection>> admission = new AtomicReference<>();
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25);
    boolean destroyed;

    static void check(boolean value) { if (!value) throw new IllegalArgumentException("Invalid local profile fixture"); }
    void alive() { check(System.nanoTime() < deadline && failure.get() == null); }

    void install(DataChannel channel) {
        int index = List.of(LABELS).indexOf(channel.label());
        if (index < 0 || (mask.getAndUpdate(value -> value | (1 << index)) & (1 << index)) != 0) {
            failure.compareAndSet(null, new IllegalStateException("Unexpected channel")); return;
        }
        byte[] nonce = new byte[32]; NativeDiagnosticProbe.RANDOM.nextBytes(nonce);
        AtomicBoolean started = new AtomicBoolean(), answered = new AtomicBoolean(), replied = new AtomicBoolean();
        AtomicInteger received = new AtomicInteger();
        Runnable start = () -> {
            if (!started.compareAndSet(false, true)) return;
            try {
                var reliability = channel.reliability();
                check(reliability.isUnordered() == (index == 1) && reliability.isUnreliable() == (index == 1));
                check(reliability.maxRetransmits() == 0 && reliability.maxPacketLifeTime().isZero());
                opened.incrementAndGet(); send(channel, index, 1, nonce);
            } catch (Throwable error) { failure.compareAndSet(null, error); }
        };
        channel.onMessage.register(DataChannelCallback.Message.handleBinary((dc, bytes) -> {
            try {
                check(received.incrementAndGet() <= 2 && bytes.remaining() == FRAME_SIZE);
                check(bytes.get() == 0 && bytes.getInt() == MAGIC && bytes.get() == index);
                int kind = bytes.get(); byte[] value = new byte[32]; bytes.get(value);
                if (kind == 1) { check(answered.compareAndSet(false, true)); send(dc, index, 2, value); }
                else { check(kind == 2 && Arrays.equals(value, nonce) && replied.compareAndSet(false, true)); completed.incrementAndGet(); }
            } catch (Throwable error) { failure.compareAndSet(null, error); }
        }));
        channel.onOpen.register(dc -> start.run());
        if (channel.isOpen()) start.run();
    }
    static void send(DataChannel channel, int index, int kind, byte[] nonce) {
        ByteBuffer bytes = ByteBuffer.allocateDirect(FRAME_SIZE);
        bytes.put((byte)0).putInt(MAGIC).put((byte)index).put((byte)kind).put(nonce).flip();
        channel.sendMessage(bytes);
    }
    void track(PeerConnection value) {
        value.onIceStateChange.register((p, state) -> {
            if (state == IceState.RTC_ICE_CONNECTED || state == IceState.RTC_ICE_COMPLETED) ice.set(true);
        });
        value.onStateChange.register((p, state) -> { if (state == PeerState.RTC_FAILED) failure.compareAndSet(null, new IllegalStateException("DTLS failed")); });
        value.onDataChannel.register((p, channel) -> install(channel));
    }
    void closePeer(PeerConnection value) { if (value != null) check(value.closeAndAwait(Duration.ofSeconds(5))); }

    void run(Path config) throws Exception {
        Map<String, String> values = new java.util.HashMap<>();
        for (String line : NativeDiagnosticRole.privateRead(config).split("\n")) {
            if (line.isEmpty()) continue;
            int split = line.indexOf('='); check(split > 0 && !line.contains("\\") && !line.contains("\r"));
            check(values.putIfAbsent(line.substring(0, split), line.substring(split + 1)) == null);
        }
        check(values.keySet().equals(Set.of("mode", "offerPath", "answerPath", "certificatePath", "keyPath", "expiresAtMillis")));
        String mode = values.get("mode"); check(Set.of("first-contact", "assisted").contains(mode));
        long expires = Long.parseLong(values.get("expiresAtMillis"));
        check(expires > System.currentTimeMillis() && expires <= System.currentTimeMillis() + 30000);
        for (String name : List.of("offerPath", "answerPath", "certificatePath", "keyPath")) check(Path.of(values.get(name)).isAbsolute());
        String offer = NativeDiagnosticRole.privateRead(Path.of(values.get("offerPath")));
        Path certificate = Path.of(values.get("certificatePath")), key = Path.of(values.get("keyPath"));
        NativeDiagnosticRole.privateRead(certificate); NativeDiagnosticRole.privateRead(key);
        for (String prefix : List.of("a=ice-ufrag:", "a=ice-pwd:", "a=fingerprint:", "m=", "a=mid:", "a=candidate:"))
            check(offer.lines().filter(line -> line.startsWith(prefix)).count() == 1);
        check(offer.contains("m=application ") && NativeTransportProbe.field(offer, "mid").equals("0"));
        var candidate = IceCandidate.parse(offer.lines().filter(line -> line.startsWith("a=candidate:")).findFirst().orElseThrow());
        check(candidate.transport() == IceCandidate.Transport.UDP && candidate.type() == IceCandidate.Type.HOST);
        InetAddress address = NativeDiagnosticRole.numeric(candidate.address().getHostString());
        // This executable cannot target another machine, even if given a malicious SDP file.
        check(NetworkInterface.getByInetAddress(address) != null && !address.isAnyLocalAddress() && !address.isMulticastAddress());
        int remotePort = candidate.address().getPort(), port;
        check(remotePort > 0 && remotePort <= 65535);
        try (DatagramSocket reserve = new DatagramSocket(new InetSocketAddress(address, 0))) { port = reserve.getLocalPort(); }
        String remoteUfrag = NativeTransportProbe.field(offer, "ice-ufrag");
        String remotePassword = NativeTransportProbe.field(offer, "ice-pwd");
        check(remoteUfrag.matches("[A-Za-z0-9+/]{4,256}") && remotePassword.matches("[A-Za-z0-9+/]{22,256}"));
        check(NativeTransportProbe.field(offer, "fingerprint").matches("sha-256 (?:[A-F0-9]{2}:){31}[A-F0-9]{2}"));
        String localUfrag = NativeDiagnosticProbe.randomCredential(), localPassword = NativeDiagnosticProbe.randomCredential();
        Object guard = new Object();
        IceUdpMuxListener mux = new IceUdpMuxListener(address, port, 1, Duration.ofSeconds(3), Runnable::run, request -> {
            synchronized (guard) {
                try {
                    if (closing.get() || System.currentTimeMillis() >= expires
                        || !NativeDiagnosticRole.numeric(request.remoteAddress()).equals(address) || request.remotePort() != remotePort
                        || !request.localUfrag().equals(localUfrag) || !request.remoteUfrag().equals(remoteUfrag)) return CompletableFuture.completedFuture(null);
                    if (mode.equals("assisted")) return CompletableFuture.completedFuture(peer.get() == null ? null
                        : IceUdpMuxListener.Acceptance.reuse(peer.get(), Instant.ofEpochMilli(expires)));
                    if (admission.get() != null) return CompletableFuture.completedFuture(null);
                    CompletableFuture<PeerConnection> accepted = request.completion().toCompletableFuture(); admission.set(accepted);
                    return CompletableFuture.completedFuture(IceUdpMuxListener.Acceptance.builder(offer, localPassword)
                        .identity(new DtlsIdentity(certificate, key)).expiresAt(Instant.ofEpochMilli(expires)).initialize(this::track).build());
                } catch (Exception error) { failure.compareAndSet(null, error); return CompletableFuture.completedFuture(null); }
            }
        });
        try {
            String answer;
            if (mode.equals("assisted")) {
                PeerConnection host = PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withBindAddress(address)
                    .withEnableIceUdpMux(true).withDisableAutoNegotiation(true).withIceServers(List.of())
                    .withPortRangeBegin(port).withPortRangeEnd(port), Runnable::run, certificate, key, null);
                peer.set(host); track(host);
                AtomicBoolean gathered = new AtomicBoolean();
                host.onGatheringStateChange.register((p, state) -> { if (state == GatheringState.RTC_GATHERING_COMPLETE) gathered.set(true); });
                host.setRemoteDescription(offer, SessionDescriptionType.OFFER);
                host.setLocalDescription("answer", localUfrag, localPassword);
                while (!gathered.get()) { alive(); Thread.sleep(5); }
                StringBuilder text = new StringBuilder();
                for (String line : host.localDescription().split("\r?\n"))
                    if (!line.isEmpty() && !line.startsWith("a=candidate:") && !line.equals("a=end-of-candidates")) text.append(line).append("\r\n");
                text.append("a=candidate:1 1 UDP 2130706431 ").append(address.getHostAddress()).append(' ').append(port).append(" typ host\r\na=end-of-candidates\r\n");
                answer = text.toString();
            } else {
                check(mux.statistics().agents() == 0 && mux.statistics().notifications() == 0);
                answer = NativeDiagnosticProbe.answer(address.getHostAddress(), port, localUfrag, localPassword, NativeDiagnosticProbe.fingerprint(certificate));
            }
            Path output = Path.of(values.get("answerPath")), temporary = Files.createTempFile(output.getParent(), ".profile-", ".tmp");
            try { Files.writeString(temporary, answer); Files.createLink(output, temporary); } finally { Files.deleteIfExists(temporary); }
            System.out.println("{\"event\":\"answer_ready\",\"testOwnedAdmission\":true}");
            while (completed.get() < 2) { alive(); check(System.currentTimeMillis() < expires); Thread.sleep(5); }
            if (mode.equals("first-contact")) peer.set(admission.get().get(3, TimeUnit.SECONDS));
            var selected = peer.get().selectedCandidatePair();
            check(selected.remote().getPort() == remotePort && selected.local().getPort() == port
                && NativeDiagnosticRole.numeric(selected.remote().getHostString()).equals(address));
            check(mask.get() == 3 && opened.get() == 2 && mux.statistics().agents() == 1);
            System.out.println("{\"event\":\"round_trips_complete\",\"roundTrips\":2}");
            Thread.sleep(500);
            alive(); // A late malformed frame or duplicate channel must invalidate the result.
            closePeer(peer.get());
            check(failure.get() == null && mux.statistics().agents() == 0
                && mux.statistics().mappedTuples() == 0 && mux.statistics().pendingRequests() == 0);
            System.out.println("{\"event\":\"transport_complete\",\"roundTrips\":2,\"channels\":2,\"family\":"
                + (address.getAddress().length == 4 ? 4 : 6) + ",\"mode\":\"" + mode + "\",\"gameplay\":false}");
        } finally {
            synchronized (guard) { closing.set(true); }
            try {
                PeerConnection accepted = null;
                try {
                    accepted = admission.get() == null ? null : admission.get().handle((value, error) -> value).get(5, TimeUnit.SECONDS);
                    closePeer(accepted);
                } finally { if (peer.get() != accepted) closePeer(peer.get()); }
            } finally { mux.close(); }
            // A failed peer OR listener close must leave the negative-case cleanup evidence false.
            destroyed = true;
        }
    }
    public static void main(String[] args) {
        NativeMinecraftProfileHost host = new NativeMinecraftProfileHost();
        try {
            check(args.length == 2 && args[0].equals("--config"));
            LibDataChannel.setLogLevel(LibDataChannel.LogLevel.NONE);
            host.run(Path.of(args[1]));
            System.out.println("{\"event\":\"closed\",\"transportDestroyed\":true}");
        } catch (Throwable error) {
            System.out.println("{\"event\":\"failed\",\"channels\":" + host.opened.get() + ",\"iceConnected\":" + host.ice.get()
                + ",\"transportDestroyed\":" + host.destroyed + ",\"errorType\":\"" + error.getClass().getSimpleName() + "\"}");
            System.exit(1);
        }
    }
}
