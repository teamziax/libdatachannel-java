package tel.schich.libdatachannel;

import java.net.InetSocketAddress;
import java.util.Locale;
import java.util.Objects;

/** Owned selected ICE candidate metadata. Parsing never performs DNS resolution. */
public final class IceCandidate {
    public enum Type { HOST, SERVER_REFLEXIVE, PEER_REFLEXIVE, RELAYED, UNKNOWN }
    public enum Transport { UDP, TCP, UNKNOWN }

    private final String sdp, foundation, transportName, typeName, extensionAttributes;
    private final int component;
    private final long priority;
    private final InetSocketAddress address;

    private IceCandidate(String sdp, String[] fields) {
        this.sdp = sdp;
        foundation = fields[0];
        component = (int)number(fields[1], 1, 256);
        transportName = fields[2];
        priority = number(fields[3], 0, 0xffff_ffffL);
        address = InetSocketAddress.createUnresolved(fields[4], (int)number(fields[5], 1, 65535));
        typeName = fields[7];
        extensionAttributes = fields.length == 9 ? fields[8] : "";
    }

    private static long number(String value, long minimum, long maximum) {
        if (value.isEmpty() || !value.chars().allMatch(c -> c >= '0' && c <= '9')) throw new IllegalArgumentException("Invalid ICE candidate number");
        long number = Long.parseLong(value);
        if (number < minimum || number > maximum) throw new IllegalArgumentException("ICE candidate number outside range");
        return number;
    }

    public static IceCandidate parse(String sdp) {
        Objects.requireNonNull(sdp, "sdp");
        if (sdp.length() >= 65536 || sdp.chars().anyMatch(c -> c < 0x20 || c > 0x7e))
            throw new IllegalArgumentException("ICE candidate must be a bounded ASCII line");
        String line = sdp.startsWith("a=") ? sdp.substring(2) : sdp;
        if (!line.startsWith("candidate:")) throw new IllegalArgumentException("Missing ICE candidate prefix");
        String[] fields = line.substring("candidate:".length()).trim().split(" +", 9);
        if (fields.length < 8 || !fields[6].equals("typ")) throw new IllegalArgumentException("Invalid ICE candidate fields");
        return new IceCandidate(sdp, fields);
    }

    public String sdp() { return sdp; }
    public String foundation() { return foundation; }
    public int component() { return component; }
    public long priority() { return priority; }
    public InetSocketAddress address() { return address; }
    public String transportName() { return transportName; }
    public String typeName() { return typeName; }
    /** Original extension tail, retaining related address/port, TCP type and unknown fields. */
    public String extensionAttributes() { return extensionAttributes; }

    public Transport transport() {
        switch (transportName.toUpperCase(Locale.ROOT)) {
            case "UDP": return Transport.UDP;
            case "TCP": return Transport.TCP;
            default: return Transport.UNKNOWN;
        }
    }

    public Type type() {
        switch (typeName) {
            case "host": return Type.HOST;
            case "srflx": return Type.SERVER_REFLEXIVE;
            case "prflx": return Type.PEER_REFLEXIVE;
            case "relay": return Type.RELAYED;
            default: return Type.UNKNOWN;
        }
    }
}
