package tel.schich.libdatachannel;

import org.eclipse.jdt.annotation.Nullable;
import java.net.Inet6Address;
import java.net.InetSocketAddress;

/** Immutable actual-send budget. Its deadline uses the native monotonic clock, never a refreshed TTL. */
public final class UdpSendLimits {
    final long maxDatagrams, deadlineMonotonicMillis;
    final int maxPayloadBytes, destinationPort;
    final @Nullable String destinationAddress;

    public UdpSendLimits(long maxDatagrams, int maxPayloadBytes, long deadlineMonotonicMillis,
                         @Nullable InetSocketAddress destination) {
        if (maxDatagrams < 1 || maxDatagrams > 0xffff_ffffL || maxPayloadBytes < 1 || maxPayloadBytes > 65507 || deadlineMonotonicMillis < 1)
            throw new IllegalArgumentException("Invalid UDP send limits");
        if (destination != null && (destination.isUnresolved() || destination.getPort() == 0 || destination.getAddress().isAnyLocalAddress()
                || destination.getAddress() instanceof Inet6Address && ((Inet6Address) destination.getAddress()).getScopeId() != 0))
            throw new IllegalArgumentException("Resolved numeric UDP destination without a scope required");
        this.maxDatagrams = maxDatagrams; this.maxPayloadBytes = maxPayloadBytes; this.deadlineMonotonicMillis = deadlineMonotonicMillis;
        this.destinationAddress = destination == null ? null : destination.getAddress().getHostAddress();
        this.destinationPort = destination == null ? 0 : destination.getPort();
    }
    public long maxDatagrams() { return maxDatagrams; }
    public int maxPayloadBytes() { return maxPayloadBytes; }
    public long deadlineMonotonicMillis() { return deadlineMonotonicMillis; }
    /** Capture before admission/crypto work; carry the resulting fixed deadline through peer construction. */
    public static long monotonicTimeMillis() { LibDataChannel.initialize(); return clockNative(); }
    private static native long clockNative();
    static native long @Nullable [] statsNative(int peer);
}
