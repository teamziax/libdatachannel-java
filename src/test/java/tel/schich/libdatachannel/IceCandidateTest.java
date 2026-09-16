package tel.schich.libdatachannel;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IceCandidateTest {
    @Test
    void retainsSelectedCandidateTypesAndFullMetadataWithoutDns() {
        String local = "candidate:f1 1 UDP 4294967295 192.0.2.10 40000 typ srflx raddr 10.0.0.1 rport 19132";
        String remote = "a=candidate:f2 1 tcp 123 2001:db8::10 65535 typ relay tcptype passive raddr 2001:db8::20 rport 40001 generation 0";
        CandidatePair pair = CandidatePair.parse(local, remote);
        assertEquals("192.0.2.10", pair.local().getHostString());
        assertEquals(40000, pair.local().getPort());
        assertEquals("2001:db8::10", pair.remote().getHostString());
        assertEquals(65535, pair.remote().getPort());
        assertTrue(pair.local().isUnresolved());
        var first = pair.localCandidate().orElseThrow();
        var second = pair.remoteCandidate().orElseThrow();
        assertEquals(IceCandidate.Type.SERVER_REFLEXIVE, first.type());
        assertEquals(IceCandidate.Transport.UDP, first.transport());
        assertEquals(4294967295L, first.priority());
        assertEquals("f1", first.foundation());
        assertEquals(1, first.component());
        assertEquals(local, first.sdp());
        assertEquals(IceCandidate.Type.RELAYED, second.type());
        assertEquals(IceCandidate.Transport.TCP, second.transport());
        assertEquals("tcptype passive raddr 2001:db8::20 rport 40001 generation 0", second.extensionAttributes());
        var future = IceCandidate.parse("candidate:f 1 FUTURE 1 no-dns.invalid 9 typ future extension kept");
        assertEquals(IceCandidate.Type.UNKNOWN, future.type());
        assertEquals(IceCandidate.Transport.UNKNOWN, future.transport());
        assertEquals("future", future.typeName());
        assertEquals("no-dns.invalid", future.address().getHostString());
    }

    @Test
    void rejectsMalformedAndOversizedCandidateMetadata() {
        for (String candidate : new String[] {
            "127.0.0.1:19132", "candidate:f 1 UDP 1 127.0.0.1 9 type host",
            "candidate:f 1 UDP 4294967296 127.0.0.1 9 typ host",
            "candidate:f 0 UDP 1 127.0.0.1 9 typ host",
            "candidate:f 1 UDP 1 127.0.0.1 65536 typ host",
            "candidate:f 1 UDP 1 127.0.0.1 9 typ host\nextra",
            "candidate:f 1 UDP 1 127.0.0.1 9 typ host " + "x".repeat(65536)}) {
            assertThrows(IllegalArgumentException.class, () -> IceCandidate.parse(candidate));
        }
    }
}
