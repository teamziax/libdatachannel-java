# Optional native UDP budgets

`PeerConnection.createPeerWithUdpLimits(...)` and
`IceUdpMuxListener.Acceptance.Builder.udpSendLimits(...)` install immutable
libjuice limits before gathering or incoming acceptance. Existing constructors
remain unlimited. Reusing an accepted peer retains its exact agent and budget.
The C ABI configuration struct and preexisting JNI entrypoints are unchanged.

Capture `UdpSendLimits.monotonicTimeMillis()` before asynchronous authorization
and add only the already authorized remaining duration. Carry this fixed native
deadline through acceptance; never reset it on retries or reuse. The optional
destination must be an already resolved numeric socket address. It is copied
through JNI into native owned storage. No Java hostname resolution is done by
the budget constructor. Unsupported TCP, non-mux, local TURN/relay-only, proxy
and libnice configurations reject before network activity.

The actual UDP OS send path enforces counts, payload sizes, deadline and optional
destination tuple on ICE/STUN, DTLS and SCTP, including retransmissions. Failed
OS attempts consume a reservation too. `PeerConnection.udpSendStats()` returns
an owned atomic snapshot, or empty if no limited ICE agent exists. Counters are
not delivery/reachability proof. Expiry/exhaustion deny sends; the caller must
close and await native cleanup. Shared listeners and other agents remain alive.

For a 1200-byte UDP payload cap configure MTU1248 (IPv6/UDP overhead48). The
native guard still rejects oversized sends if the MTU is misconfigured.
These are generic transport limits, not workload or diagnostic authorization.

`./gradlew nativeUdpSendLimitsProbe nativeDiagnosticProbe` runs actual local
transport tests with the pinned native source. Tests use their own admission
fixtures and certificates. Both IPv4 and IPv6 cover full ICE/DTLS/SCTP channel
traffic, exact count exhaustion, absolute expiry, inadequate count/size before
DTLS, and continued traffic on a simultaneous unlimited peer on the same host
mux. An additional tuple-reuse case proves the original agent retains its limit.
This is not a signed diagnostic gate, stock-client gameplay, or public NAT test.

The Java library remains Java11-compatible; native probe executables use Java17.
The native dependency pins in this branch are unpublished integration commits.
