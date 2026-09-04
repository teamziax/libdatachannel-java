package tel.schich.libdatachannel;

import java.net.InetAddress;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Exclusive raw UDP ingress gate, before ICE tuple lookup or flow promotion.
 * The endpoint owns one socket even with zero peers. The handler runs on the
 * native mux thread and must do bounded, nonblocking work. It MUST NOT call
 * native APIs (including peer creation, stats, or close). Queue creation after
 * validating admission; retain the first packet and replay it after peer setup.
 * Close peers first; removal of this gate leaves remaining peers fail-closed.
 */
public final class RawUdpMuxListener implements AutoCloseable {
    @FunctionalInterface
    public interface Handler {
        /** Packet is a Java-owned copy. True permits ordinary ICE processing. */
        boolean accept(byte[] packet, String address, int port);
    }

    private static final ThreadLocal<Boolean> IN_CALLBACK = ThreadLocal.withInitial(() -> false);
    private final Handler handler;
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private long handle;

    public RawUdpMuxListener(InetAddress bindAddress, int port, Handler handler) {
        outsideCallback();
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Explicit UDP port required");
        this.handler = Objects.requireNonNull(handler, "handler");
        LibDataChannel.initialize();
        handle = openNative(Objects.requireNonNull(bindAddress, "bindAddress").getHostAddress(), port);
        if (handle == 0) throw new IllegalStateException("Cannot acquire raw UDP mux endpoint");
    }

    // JNI calls only this method. Exceptions never escape onto native threads.
    @SuppressWarnings("unused")
    private boolean dispatch(byte[] packet, String address, int port) {
        IN_CALLBACK.set(true);
        try {
            return failure.get() == null && handler.accept(packet, address, port);
        } catch (Throwable error) {
            failure.compareAndSet(null, error);
            return false;
        } finally {
            IN_CALLBACK.remove();
        }
    }

    public Throwable failure() { return failure.get(); }

    /**
     * Queue a retained STUN request after its peer has been configured. The native
     * mux thread re-runs the current handler before ordinary ICE processing, so
     * expired/cancelled reservations cannot bypass admission. Copies at most
     * 2048 bytes into a queue bounded to 1024 packets; failure throws. No callbacks
     * run inline. Must be called outside the ingress callback.
     */
    public void replay(byte[] packet, InetAddress sourceAddress, int sourcePort) {
        outsideCallback();
        Objects.requireNonNull(packet, "packet");
        Objects.requireNonNull(sourceAddress, "sourceAddress");
        if (packet.length < 20 || packet.length > 2048 || packet[0] != 0 || packet[1] != 1 ||
            sourcePort < 1 || sourcePort > 65535) throw new IllegalArgumentException("STUN request and source tuple required");
        synchronized (this) {
            if (handle == 0) throw new IllegalStateException("Endpoint closed");
            replayNative(handle, packet, sourceAddress.getHostAddress(), sourcePort);
        }
    }

    /** Processed datagrams (including replays), rejected, native ICE agents, promoted UDP tuples. */
    public long[] stats() {
        outsideCallback();
        synchronized (this) {
        if (handle == 0) throw new IllegalStateException("Endpoint closed");
        return statsNative(handle);
        }
    }

    @Override
    public void close() {
        outsideCallback();
        synchronized (this) {
        if (handle != 0) {
            closeNative(handle);
            handle = 0;
        }
        }
    }

    static void outsideCallback() {
        if (IN_CALLBACK.get()) throw new IllegalStateException("Native mux APIs cannot run in an ingress callback");
    }
    private native long openNative(String address, int port);
    private static native void closeNative(long handle);
    private static native long[] statsNative(long handle);
    private static native void replayNative(long handle, byte[] packet, String sourceAddress, int sourcePort);
}
