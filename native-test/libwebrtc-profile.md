# Same-machine libwebrtc profile fixture

`NativeMinecraftProfileHost` is a test executable in the `nativeProbe` source set.
It is not shipped as a public listener or a regional probe. The independent peer
is Chromium/libwebrtc, driven by Warden's `scripts/connectivity-lab/libwebrtc-local.mjs`.

Build `writeNativeDiagnosticLaunch` and use its generated
`build/native-diagnostic-argv.txt`. The browser harness reads this as an argument
array and selects `tel.schich.libdatachannel.NativeMinecraftProfileHost` as the
main class. It never evaluates the file as shell code. This keeps the exact JDK,
native binary and dependency classpath from the native build.

The private `--config` file supplies `mode`, `offerPath`, `answerPath`,
`certificatePath`, `keyPath` and `expiresAtMillis`. Inputs must be owner-only regular
files. The offer has exactly one numeric UDP host candidate on a local interface;
the host binds that same local address and admits only the exact offered UDP
source port and ICE usernames. It cannot target a remote machine. A fixed
25-second monotonic deadline and an absolute deadline of at most 30 seconds apply.
First-contact admission creates no peer before the authenticated incoming ICE
request; assisted mode explicitly prepares one known peer on that same mux.

The two channel labels and negotiated settings match the documented Minecraft
transport profile: `ReliableDataChannel` is ordered and reliable;
`UnreliableDataChannel` is unordered with zero retransmissions. Each 39-byte
message begins with NetherNet's zero single-fragment header, then a fixed test
marker, channel/kind and 32 random challenge bytes. Each endpoint independently
challenges the other on each channel. Incorrect, duplicate or extra frames fail.
The final drain is checked too, and cleanup is reported only after successful
peer and listener teardown.

The private coordinator pins the host certificate; native DTLS verifies the
offered client fingerprint. This is **test-owned admission**, with no Warden
diagnostic permit, player identity assertion, Minecraft packet or game pipeline.
It proves interoperability for the recorded browser/native build and selected
local path. External routing, kernel NAT cases with this peer, signed probe
admission, stock-client gameplay and platform-specific release acceptance remain
separate checks. It does not add an external UDP execution mode or claim a native
datagram budget.
