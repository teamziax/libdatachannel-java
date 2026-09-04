# Native admission feasibility probe

```sh
git submodule update --init --recursive
./gradlew nativeAdmissionProbe --no-daemon -Plibdatachannel.java-compiler-version=17
```

Requires Linux x86_64, JDK 17, CMake, a C/C++ compiler, OpenSSL development files and
`openssl` CLI. Compiles the binding with `--release 11`, runs the probe with JDK 17,
and keeps the existing JNI `.so` packaging. This focused command uses system
OpenSSL; it is a developer test artifact, not the portable dockcross release.
Ports 49184 and the client ephemeral UDP port must be free. The generated one-day
certificate/key live under ignored `build/probe-identity`, never source control.

The simulated signalling side encrypts the client's minimal ICE/DTLS/SCTP context
into a server ICE ufrag and creates an answer using only the provisioned host
profile. The host receives neither offer nor command. Raw STUN delivers the token;
AEAD and MESSAGE-INTEGRITY verification precede the directly instrumented C API
construction boundary. Only then is a remote description reconstructed and a peer
created. Both channels open and deliver distinct binary payloads. Runs cover 167,
178 and 256 characters; a wrong token-bound fingerprint fails DTLS with no channels.

This is a bounded mechanism test, **not production admission policy**, stock-client
evidence, gameplay or a Worker integration test. The Warden adapter owns bounded
replay/key/expiry/queue policy and consumes canonical fixtures separately. Do not
reuse the test secret or this simulated signer's fixed profile in production.

The library exposes `RawUdpMuxListener`, fixed identity `PeerConnection.createPeer`
overload, explicit-ICE `setLocalDescription`, and native creation-attempt statistics.
Callback work must be bounded and must not call native APIs. The listener copies
packet bytes into Java, fails closed on handler exceptions, and waits for native
callbacks before releasing its global reference on close.

From a clean commit, `scripts/package-admission-development.sh [maven-directory]`
produces an immutable `dev.ziax.warden:libdatachannel-java:0.24.1.1-warden.<full SHA>`
Java jar and Linux x86_64 classifier jar. It tests first and only writes the explicit
local destination. It does not upload, merge or deploy. The original Maven group
and normal platform release build remain separate.

The probe now includes a deterministic C++ teardown regression. CI demonstrated
that ordinary peer deletion can return before the ICE agent is destroyed. The
regression deliberately stalls the native teardown worker, proves the old API's
behavior, checks that the bounded completion API reports timeout rather than
success, and then checks zero agents after successful completion. The Java host
uses `closeAndAwait(Duration)` on its external owner thread before freeing
capacity; this method rejects calls from mux/event callbacks. The primitive
probe retains the immediate zero-agent assertion between endpoint reuses.

Worker CI run 33830909678 exposed a remaining transport-reference race in the
initial completion hook: the teardown task had released its references, while
another callback/task still retained the ICE transport. The native regression
now holds an explicit extra ICE reference, waits for the teardown task to finish,
and requires the bounded API to report timeout while the agent remains. The
completion hook counts actual transport destruction, without blocking the teardown
worker. Releasing the last reference completes the wait and leaves zero agents.
