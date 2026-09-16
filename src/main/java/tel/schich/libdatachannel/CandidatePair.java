package tel.schich.libdatachannel;

import tel.schich.jniaccess.JNIAccess;

import java.net.InetSocketAddress;
import java.util.Optional;

public class CandidatePair {
    private final InetSocketAddress local;
    private final InetSocketAddress remote;
    private final IceCandidate localCandidate, remoteCandidate;

    public CandidatePair(InetSocketAddress local, InetSocketAddress remote) {
        this.local = local;
        this.remote = remote;
        this.localCandidate = null;
        this.remoteCandidate = null;
    }

    private CandidatePair(IceCandidate local, IceCandidate remote) {
        this.local = local.address();
        this.remote = remote.address();
        this.localCandidate = local;
        this.remoteCandidate = remote;
    }

    public InetSocketAddress local() {
        return local;
    }

    public InetSocketAddress remote() {
        return remote;
    }

    /** Present for native-selected pairs; absent for manually constructed address-only pairs. */
    public Optional<IceCandidate> localCandidate() { return Optional.ofNullable(localCandidate); }
    public Optional<IceCandidate> remoteCandidate() { return Optional.ofNullable(remoteCandidate); }

    @JNIAccess
    static CandidatePair parse(String local, String remote) {
        return new CandidatePair(IceCandidate.parse(local), IceCandidate.parse(remote));
    }
}
