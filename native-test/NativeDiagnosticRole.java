package tel.schich.libdatachannel;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Isolated-lab first-contact/assisted executable; test-owned credentials, no provider permit or UDP-budget claim. */
public final class NativeDiagnosticRole {
    static final Set<String> KEYS = Set.of("version", "role", "mode", "bindAddress", "localPort", "peerAddress", "peerPort",
        "publicAddress", "publicPort", "expiresAtMillis", "maxDurationMillis", "certificatePath", "keyPath",
        "localUfrag", "localPassword", "remoteUfrag", "remotePassword", "remoteFingerprint", "offerPath", "answerPath");
    final Map<String, String> config;
    final long deadline;
    final InetAddress bind, peerAddress;
    final int localPort, peerPort;
    final AtomicReference<Throwable> failure = new AtomicReference<>();
    final AtomicInteger opened = new AtomicInteger();
    final AtomicInteger channelMask = new AtomicInteger();
    final AtomicBoolean iceConnected = new AtomicBoolean();
    final CountDownLatch roundTrips = new CountDownLatch(2);
    volatile long lastAgents;
    volatile long lastNotifications;
    volatile boolean transportDestroyed;

    static void require(boolean condition) { if (!condition) throw new IllegalArgumentException("Invalid diagnostic configuration or state"); }

    static String privateRead(Path path) throws Exception {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS));
        require(Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rw-------")));
        require(Files.size(path) <= 65536);
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    static InetAddress numeric(String value) throws Exception {
        require(value.matches("[0-9a-fA-F:.]+") && (value.contains(":") || value.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")));
        return InetAddress.getByName(value);
    }

    long number(String key, long minimum, long maximum) {
        String value = config.get(key); require(value != null && value.matches("[0-9]+"));
        long parsed = Long.parseLong(value); require(parsed >= minimum && parsed <= maximum); return parsed;
    }

    NativeDiagnosticRole(Path file) throws Exception {
        config = new HashMap<>();
        for (String line : privateRead(file).split("\n")) {
            if (line.isEmpty()) continue;
            int separator = line.indexOf('=');
            require(separator > 0 && !line.contains("\\") && !line.contains("\r") && !line.contains("\0"));
            String key = line.substring(0, separator), value = line.substring(separator + 1);
            require(KEYS.contains(key) && !value.isEmpty() && config.putIfAbsent(key, value) == null);
        }
        require(config.keySet().equals(KEYS));
        require(config.get("version").equals("1") && Set.of("first-contact", "assisted").contains(config.get("mode")));
        require(Set.of("host", "client").contains(config.get("role")));
        long duration = number("maxDurationMillis", 1000, 120000);
        long expires = number("expiresAtMillis", 1, Long.MAX_VALUE), remaining = expires - System.currentTimeMillis();
        require(remaining > 0 && remaining <= 120000);
        deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.min(duration, remaining));
        bind = numeric(config.get("bindAddress")); peerAddress = numeric(config.get("peerAddress"));
        require(bind.getClass() == peerAddress.getClass() && bind.getClass() == numeric(config.get("publicAddress")).getClass());
        localPort = (int)number("localPort", 1, 65535); peerPort = (int)number("peerPort", 1, 65535);
        number("publicPort", 1, 65535);
        for (String key : List.of("localUfrag", "localPassword", "remoteUfrag", "remotePassword")) require(config.get(key).matches("[a-f0-9]{32}"));
        require(config.get("remoteFingerprint").matches("(?:[A-F0-9]{2}:){31}[A-F0-9]{2}"));
        for (String key : List.of("certificatePath", "keyPath", "offerPath", "answerPath")) require(Path.of(config.get(key)).isAbsolute());
        privateRead(Path.of(config.get("keyPath")));
    }

    void alive() {
        require(System.nanoTime() < deadline && System.currentTimeMillis() < Long.parseLong(config.get("expiresAtMillis")));
        if (failure.get() != null) throw new IllegalStateException("Diagnostic transport failed");
    }

    String awaitFile(String key) throws Exception {
        Path path = Path.of(config.get(key));
        while (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) { alive(); Thread.sleep(10); }
        return privateRead(path);
    }

    void writeFile(String key, String value) throws Exception {
        Path path = Path.of(config.get(key));
        Path temporary = Files.createTempFile(path.getParent(), ".diagnostic-", ".tmp",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            Files.writeString(temporary, value, StandardCharsets.UTF_8);
            // Publish a completed file atomically without replacing a stale attempt.
            Files.createLink(path, temporary);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    void validateRemote(String sdp) throws Exception {
        require(sdp.length() <= 65536 && !sdp.contains("\0"));
        require(NativeTransportProbe.field(sdp, "fingerprint").equals("sha-256 " + config.get("remoteFingerprint")));
        require(NativeTransportProbe.field(sdp, "ice-ufrag").equals(config.get("remoteUfrag")));
        require(NativeTransportProbe.field(sdp, "ice-pwd").equals(config.get("remotePassword")));
        for (String prefix : List.of("a=fingerprint:", "a=ice-ufrag:", "a=ice-pwd:", "m="))
            require(sdp.lines().filter(line -> line.startsWith(prefix)).count() == 1);
        require(sdp.lines().filter(line -> line.startsWith("m=")).allMatch(line -> line.startsWith("m=application ")));
        int candidates = 0;
        for (String line : sdp.split("\r?\n")) if (line.startsWith("a=candidate:")) {
            IceCandidate candidate = IceCandidate.parse(line);
            require(candidate.transport() == IceCandidate.Transport.UDP && candidate.type() == IceCandidate.Type.HOST);
            require(numeric(candidate.address().getHostString()).equals(peerAddress) && candidate.address().getPort() == peerPort);
            ++candidates;
        }
        require(candidates == 1);
    }

    void install(DataChannel channel) {
        int index = List.of(NativeDiagnosticProbe.LABELS).indexOf(channel.label());
        if (index < 0) { failure.compareAndSet(null, new IllegalStateException("Unexpected channel")); return; }
        int bit = 1 << index;
        if ((channelMask.getAndUpdate(value -> value | bit) & bit) != 0) {
            failure.compareAndSet(null, new IllegalStateException("Duplicate channel")); return;
        }
        NativeDiagnosticProbe.install(channel, index, roundTrips, opened, failure);
    }

    void track(PeerConnection peer) {
        peer.onIceStateChange.register((p, state) -> {
            if (state == IceState.RTC_ICE_CONNECTED || state == IceState.RTC_ICE_COMPLETED) iceConnected.set(true);
        });
        peer.onStateChange.register((p, state) -> {
            if (state == PeerState.RTC_FAILED) failure.compareAndSet(null, new IllegalStateException("Transport failed"));
        });
    }

    String withPublicCandidate(String sdp) {
        StringBuilder result = new StringBuilder();
        for (String line : sdp.split("\r?\n"))
            if (!line.startsWith("a=candidate:") && !line.equals("a=end-of-candidates") && !line.isEmpty()) result.append(line).append("\r\n");
        result.append("a=candidate:1 1 UDP 2130706431 ").append(config.get("publicAddress")).append(' ').append(config.get("publicPort"))
            .append(" typ host\r\na=end-of-candidates\r\n");
        return result.toString();
    }

    void finish(PeerConnection peer) throws Exception {
        while (roundTrips.getCount() > 0) { alive(); Thread.sleep(10); }
        require(opened.get() == 2 && channelMask.get() == 3);
        CandidatePair selected = peer.selectedCandidatePair();
        require(numeric(selected.remote().getHostString()).equals(peerAddress) && selected.remote().getPort() == peerPort);
        // Leave a bounded drain interval for the other process's final reply.
        long drain = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(config.get("role").equals("host") ? 1000 : 500);
        while (System.nanoTime() < drain) { alive(); Thread.sleep(10); }
        System.out.println("{\"event\":\"transport_complete\",\"role\":\"" + config.get("role") + "\",\"independentRoundTrips\":2,"
            + "\"channels\":2,\"selectedTransport\":\"" + selected.remoteCandidate().orElseThrow().transportName() + "\","
            + "\"selectedType\":\"" + selected.remoteCandidate().orElseThrow().typeName() + "\",\"family\":"
            + (bind.getAddress().length == 4 ? 4 : 6) + ",\"mode\":\"" + config.get("mode")
            + "\",\"admission\":\"test-owned\",\"gameplay\":false}");
    }

    void closePeer(PeerConnection peer) {
        require(peer.closeAndAwait(Duration.ofSeconds(5)));
        transportDestroyed = true;
    }

    void client() throws Exception {
        PeerConnectionConfiguration settings = PeerConnectionConfiguration.DEFAULT.withBindAddress(bind).withDisableAutoNegotiation(true)
            .withPortRangeBegin(localPort).withPortRangeEnd(localPort).withIceServers(List.of());
        PeerConnection peer = PeerConnection.createPeer(settings, Runnable::run,
            Path.of(config.get("certificatePath")), Path.of(config.get("keyPath")), null);
        try {
            CompletableFuture<Void> gathered = new CompletableFuture<>();
            peer.onGatheringStateChange.register((p, state) -> { if (state == GatheringState.RTC_GATHERING_COMPLETE) gathered.complete(null); });
            track(peer);
            for (int index = 0; index < 2; ++index) install(peer.createDataChannel(NativeDiagnosticProbe.LABELS[index],
                DataChannelInitSettings.DEFAULT.withReliability(new DataChannelReliability(index == 1, index == 1, 0, 0))));
            peer.setLocalDescription("offer", config.get("localUfrag"), config.get("localPassword"));
            while (!gathered.isDone()) { alive(); Thread.sleep(10); }
            writeFile("offerPath", withPublicCandidate(peer.localDescription()));
            System.out.println("{\"event\":\"ready\",\"role\":\"client\",\"peerContactStarted\":false}");
            String answer = awaitFile("answerPath"); validateRemote(answer); alive();
            System.out.println("{\"event\":\"remote_description_validated\",\"role\":\"client\"}");
            peer.setRemoteDescription(answer, SessionDescriptionType.ANSWER);
            System.out.println("{\"event\":\"checks_started\",\"role\":\"client\"}");
            finish(peer);
        } finally { closePeer(peer); }
    }

    void host() throws Exception {
        if (config.get("mode").equals("assisted")) { assistedHost(); return; }
        CompletableFuture<PeerConnection> accepted = new CompletableFuture<>();
        AtomicInteger admissions = new AtomicInteger();
        AtomicReference<String> offer = new AtomicReference<>();
        Object admissionGuard = new Object();
        AtomicBoolean closing = new AtomicBoolean(), admissionStarted = new AtomicBoolean();
        PeerConnection peer = null;
        try (IceUdpMuxListener listener = new IceUdpMuxListener(bind, localPort, 1, Duration.ofSeconds(5), Runnable::run, request -> {
            synchronized (admissionGuard) {
                if (closing.get()) return CompletableFuture.completedFuture(null);
                alive();
                boolean sourceMatches;
                try { sourceMatches = numeric(request.remoteAddress()).equals(peerAddress); }
                catch (Exception invalidAddress) { sourceMatches = false; }
                if (offer.get() == null || !request.localUfrag().equals(config.get("localUfrag")) || !request.remoteUfrag().equals(config.get("remoteUfrag"))
                    || !sourceMatches || request.remotePort() != peerPort || admissions.incrementAndGet() != 1)
                    return CompletableFuture.completedFuture(null);
                admissionStarted.set(true);
            }
            request.completion().whenComplete((created, error) -> { if (error != null) accepted.completeExceptionally(error); else accepted.complete(created); });
            return CompletableFuture.completedFuture(IceUdpMuxListener.Acceptance.builder(offer.get(), config.get("localPassword"))
                .identity(new DtlsIdentity(Path.of(config.get("certificatePath")), Path.of(config.get("keyPath"))))
                .expiresAt(Instant.ofEpochMilli(Long.parseLong(config.get("expiresAtMillis"))))
                .initialize(created -> {
                    created.onDataChannel.register((p, channel) -> install(channel));
                    track(created);
                }).build());
        })) {
            System.out.println("{\"event\":\"ready\",\"role\":\"host\",\"peerContactStarted\":false}");
            String metadata = awaitFile("offerPath"); validateRemote(metadata); offer.set(metadata);
            require(listener.statistics().agents() == 0 && listener.statistics().notifications() == 0);
            writeFile("answerPath", NativeDiagnosticProbe.answer(config.get("publicAddress"), (int)number("publicPort", 1, 65535),
                config.get("localUfrag"), config.get("localPassword"), NativeDiagnosticProbe.fingerprint(Path.of(config.get("certificatePath")))));
            while (!accepted.isDone()) {
                var stats = listener.statistics(); lastAgents = stats.agents(); lastNotifications = stats.notifications();
                alive(); Thread.sleep(10);
            }
            peer = accepted.get(); finish(peer);
            closePeer(peer); peer = null;
            require(listener.statistics().agents() == 0 && listener.statistics().mappedTuples() == 0 && listener.statistics().pendingRequests() == 0);
        } finally {
            synchronized (admissionGuard) { closing.set(true); }
            if (admissionStarted.get()) {
                // Cancellation completion also waits for any prepared native peer's
                // cleanup. A successful late acceptance remains caller-owned here.
                PeerConnection owned = accepted.handle((created, error) -> created).get(5, TimeUnit.SECONDS);
                if (owned != null) closePeer(owned); else transportDestroyed = true;
            } else transportDestroyed = true;
        }
    }

    void assistedHost() throws Exception {
        PeerConnection peer = null;
        AtomicReference<PeerConnection> prepared = new AtomicReference<>();
        try (IceUdpMuxListener listener = new IceUdpMuxListener(bind, localPort, 1, Duration.ofSeconds(5), Runnable::run,
                request -> {
                    alive();
                    PeerConnection existing = prepared.get();
                    boolean sourceMatches;
                    try { sourceMatches = numeric(request.remoteAddress()).equals(peerAddress); }
                    catch (Exception invalidAddress) { sourceMatches = false; }
                    if (existing == null || !sourceMatches || request.remotePort() != peerPort ||
                        !request.localUfrag().equals(config.get("localUfrag")) || !request.remoteUfrag().equals(config.get("remoteUfrag")))
                        return CompletableFuture.completedFuture(null);
                    // The gameplay mux's pending-admission gate also applies to a
                    // prepared known peer. Native code authenticates tuple attachment.
                    return CompletableFuture.completedFuture(IceUdpMuxListener.Acceptance.reuse(existing,
                        Instant.ofEpochMilli(Long.parseLong(config.get("expiresAtMillis")))));
                })) {
            System.out.println("{\"event\":\"ready\",\"role\":\"host\",\"mode\":\"assisted\",\"peerContactStarted\":false}");
            String metadata = awaitFile("offerPath"); validateRemote(metadata); alive();
            require(listener.statistics().agents() == 0 && listener.statistics().notifications() == 0);
            PeerConnectionConfiguration settings = PeerConnectionConfiguration.DEFAULT.withBindAddress(bind)
                .withEnableIceUdpMux(true).withDisableAutoNegotiation(true).withPortRangeBegin(localPort)
                .withPortRangeEnd(localPort).withIceServers(List.of());
            peer = PeerConnection.createPeer(settings, Runnable::run,
                Path.of(config.get("certificatePath")), Path.of(config.get("keyPath")), null);
            prepared.set(peer);
            track(peer);
            peer.onDataChannel.register((p, channel) -> install(channel));
            CompletableFuture<Void> gathered = new CompletableFuture<>();
            peer.onGatheringStateChange.register((p, state) -> { if (state == GatheringState.RTC_GATHERING_COMPLETE) gathered.complete(null); });
            // This explicit cooperation may send checks before the answer reaches the
            // client. It is deliberately distinct from pristine first-contact admission.
            peer.setRemoteDescription(metadata, SessionDescriptionType.OFFER);
            peer.setLocalDescription("answer", config.get("localUfrag"), config.get("localPassword"));
            System.out.println("{\"event\":\"cooperation_started\",\"role\":\"host\",\"mode\":\"assisted\",\"peerContactStarted\":true}");
            while (!gathered.isDone()) { alive(); Thread.sleep(10); }
            lastAgents = listener.statistics().agents(); lastNotifications = listener.statistics().notifications();
            require(lastAgents == 1);
            writeFile("answerPath", withPublicCandidate(peer.localDescription())); // Never wait for ICE success before answering.
            finish(peer);
            closePeer(peer); peer = null; prepared.set(null);
            require(listener.statistics().agents() == 0 && listener.statistics().mappedTuples() == 0 && listener.statistics().pendingRequests() == 0);
        } finally { if (peer != null) closePeer(peer); else transportDestroyed = true; }
    }

    public static void main(String[] args) {
        int exit = 0;
        NativeDiagnosticRole role = null;
        try {
            require(args.length == 2 && Set.of("--config", "--validate-config").contains(args[0]));
            LibDataChannel.setLogLevel(LibDataChannel.LogLevel.NONE);
            role = new NativeDiagnosticRole(Path.of(args[1]));
            if (args[0].equals("--validate-config")) {
                System.out.println("{\"event\":\"config_valid\",\"networkStarted\":false}"); return;
            }
            if (role.config.get("role").equals("host")) role.host(); else role.client();
            System.out.println("{\"event\":\"closed\",\"transportDestroyed\":true}");
        } catch (Throwable error) {
            // Credentials, SDP and filesystem paths must not be echoed to public logs.
            System.out.println("{\"event\":\"failed\",\"reason\":\"diagnostic_not_completed\",\"errorType\":\"" + error.getClass().getSimpleName()
                + "\",\"openedChannels\":" + (role == null ? 0 : role.opened.get())
                + ",\"lastAgents\":" + (role == null ? 0 : role.lastAgents)
                + ",\"lastNotifications\":" + (role == null ? 0 : role.lastNotifications)
                + ",\"iceConnected\":" + (role != null && role.iceConnected.get())
                + ",\"transportDestroyed\":" + (role != null && role.transportDestroyed) + "}"); exit = 1;
        }
        System.exit(exit);
    }
}
