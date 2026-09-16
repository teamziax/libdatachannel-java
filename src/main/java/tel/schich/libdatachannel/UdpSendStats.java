package tel.schich.libdatachannel;

/** Atomic native send snapshot. Successful OS writes are not delivery or reachability evidence. */
public final class UdpSendStats {
    public enum Rejection { NONE, EXPIRED, COUNT, SIZE, DESTINATION, UNSUPPORTED }
    private final long reservedDatagrams, sentDatagrams, sentBytes, rejectedDatagrams;
    private final Rejection lastRejection;
    private UdpSendStats(long[] values) {
        reservedDatagrams = values[0]; sentDatagrams = values[1]; sentBytes = values[2];
        rejectedDatagrams = values[3]; lastRejection = Rejection.values()[(int)values[4]];
    }
    public long reservedDatagrams() { return reservedDatagrams; }
    public long sentDatagrams() { return sentDatagrams; }
    public long sentBytes() { return sentBytes; }
    /** Unsigned native uint64; use Long.compareUnsigned if a saturated counter is observed. */
    public long rejectedDatagrams() { return rejectedDatagrams; }
    public Rejection lastRejection() { return lastRejection; }
    static UdpSendStats fromNative(long[] values) {
        if (values.length != 5 || values[4] < 0 || values[4] >= Rejection.values().length)
            throw new IllegalStateException("Invalid native UDP statistics");
        return new UdpSendStats(values);
    }
}
