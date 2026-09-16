# Isolated diagnostic roles

These Linux test executables exchange real ICE, DTLS and SCTP traffic between separate
processes. Admission belongs to the test: it does not implement a signed provider
diagnostic principal, a production probe service, login or gameplay. Use them with a
controlled network namespace lab. Public execution still needs native datagram count
and size limits, authenticated control/secret delivery and provider permit integration.
The process deadline and bounded application messages do not substitute for UDP limits.

Build with `./gradlew :writeNativeDiagnosticLaunch`. The generated
`build/native-diagnostic-argv.txt` contains one argument per line, including the JDK 17
executable, native library path, classpath and main class. Read it as an argv array and
append `--config /absolute/private.properties`; do not interpret it as shell text.
`--validate-config` validates files and values without starting native transport.
The standalone offline regression is:

```sh
python3 native-test/diagnostic_role_config.py build/native-diagnostic-argv.txt
```

Configuration uses literal UTF-8 `key=value` lines, without escapes, comments or
duplicate keys. Unknown keys fail. All keys below are required. The config, key and
offer/answer files must be regular files with mode 0600, each no larger than 64 KiB.
Key, certificate and exchange paths must be absolute. The certificate is public;
the config, private key and SDP must stay private. Output files are published complete
without overwriting an existing attempt's file. Use a new private directory per run.

| Keys | Meaning |
| --- | --- |
| `version`, `mode` | Version `1`; mode `first-contact` or `assisted`. |
| `role` | `host` or `client`. |
| `bindAddress`, `localPort` | Numeric family-specific socket binding and fixed port. |
| `publicAddress`, `publicPort` | Exact numeric candidate advertised for this process. |
| `peerAddress`, `peerPort` | The only allowed remote candidate and observed source tuple. |
| `expiresAtMillis` | Absolute epoch-millisecond expiry, in the next 120 seconds. |
| `maxDurationMillis` | Additional monotonic duration limit, 1000–120000 ms. The earlier deadline applies. |
| `certificatePath`, `keyPath` | Ephemeral local PEM identity files. |
| `localUfrag`, `localPassword` | Independent test credentials, each 32 lowercase hexadecimal characters. |
| `remoteUfrag`, `remotePassword` | Expected counterpart credentials, same format. |
| `remoteFingerprint` | Exact expected remote SHA-256 certificate fingerprint, uppercase colon-separated hexadecimal. |
| `offerPath`, `answerPath` | Private exchange files shared by the test coordinator. |

The client constructs its offer with the explicit candidate and no external STUN or
TURN servers, publishes the private offer, then emits a readiness event before any
remote ICE description is installed. The host opens its listener, emits readiness,
validates offer metadata and publishes the answer while no peer exists. It creates a
peer only after the first incoming packet matches the exact source tuple and ICE
usernames; native STUN integrity and DTLS fingerprint checks remain enabled. Storing
private offer metadata does not send connectivity checks. The test must independently
establish the claimed source tuple; a STUN mapping toward another destination is not
proof that a NAT will use the same tuple toward this host.

In `assisted` mode the host validates the private offer, creates one peer on the same
listener mux, installs the authorized remote SDP and starts gathering before publishing
the generated answer with the explicit candidate. It emits `cooperation_started` at
that boundary. It does not wait for ICE success before returning the answer. The mux's
pending admission gate still applies to the known peer's first client request: the
handler must return `Acceptance.reuse(preparedPeer)` after exact source and ICE username
checks. Native code verifies the request integrity and attaches the source to that same
peer. Rejecting every pending callback breaks bidirectional ICE even if the host's own
outbound checks succeed. No additional transport or gameplay peer is created for reuse.

Run first-contact and assisted cases in separate fresh network namespaces/contact tables.
A later packet from a source the host already contacted is not pristine first-contact
evidence. A constructed source-dependent filter can block first-contact while allowing
the explicit assisted exchange. The client must still have a candidate the host can
actually reach; this test does not discover a NATed stock client's unknown public port,
prove arbitrary NAT combinations, or replace the stock-client compatibility gate.

Both roles must be foreground commands in a lab launcher that waits for both to exit.
A readiness marker on the client lets the launcher start the host after the offer is
available. Two channels have distinct exact names and actual negotiated settings:
ordered/reliable, and unordered/unreliable with zero retransmissions. Each side sends
one random 32-byte challenge and one response on each channel. Frames are fixed at
38 bytes, at most two are consumed per channel, duplicate channels fail, and replies
must match the independent local challenge. No game packets exist in this executable.

Each successful role reports two independent round trips, the selected native transport,
candidate type and family, then confirms native destruction. Ready or exit status alone
does not qualify reachability. A failed first-contact attempt can produce no incoming
host notification behind source-dependent filtering. Do not relabel that result as
successful assisted traversal, relay support, or proof about every NAT. A short drain
interval helps the other process finish its reply; the coordinator still requires both
independent completion reports and destruction. Native `localAddress`/`remoteAddress`
and selected-candidate fields are observations, not offered-candidate inference.

Logs contain bounded result events, not ICE passwords, SDP, key paths or fingerprints.
The config validator covers malformed keys, duplicates, expired/excessive lifetimes,
hostnames, mixed address families, ports, unsupported modes, escapes, permissions and oversized input. The
existing native diagnostic regression additionally tests both certificate-mismatch
directions and requires zero opened channels in those cases.

Failure output records whether ICE had connected, opened-channel count, the last host
agent/notification snapshot and confirmed transport destruction. The snapshot can precede
cleanup; it is not a live count after destruction. Intentional failure cases must declare
the expected nonzero exit in the lab coordinator and retain both reports. A completed
negative experiment does not mean transport succeeded. After a first-contact cancellation,
the host also settles any in-flight admission completion and closes a late accepted peer.
