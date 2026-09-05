# Native transport regressions

```sh
git submodule update --init --recursive
./gradlew :nativeTransportProbe --no-daemon --max-workers=2 -Plibdatachannel.java-compiler-version=17
```

The focused Linux x86_64 build uses JDK 17, CMake, a C/C++ compiler, system OpenSSL
development files and the `openssl` CLI. Java library bytecode remains compatible
with Java 11. The normal dockcross build remains available for portable artifacts.
These tests reserve loopback UDP ports 49184 and 49195; the underlying mux tests
also reserve their documented ports. Do not run competing listeners there.

`NativeTransportProbe` checks supplied PEM identity and explicit ICE usernames of
167, 178 and 256 characters with real ICE/DTLS/SCTP and two data channels. It also
imports a password-encrypted PEM key and verifies the expected fingerprint using
an automatically selected local description type. A raw
listener retains a valid initial STUN request until a peer is ready, then replays
it through the current guard and ordinary native ICE processing. Invalid traffic
creates no peer or tuple. An incorrect remote fingerprint fails DTLS before any
channel opens. The fixture contains only generic transport credentials.

The suite checks bounded teardown from an external owner thread, forbids waiting
inside callbacks, and preserves immediate endpoint reuse assertions. The native
teardown test stalls the worker and separately retains an extra transport
reference so completion cannot be mistaken for task submission or handle removal.
`CallbackCleanupProbe` closes 100 peers using alternating asynchronous/bounded
close and verifies all peer/channel wrappers become collectible without native
invalid-handle errors. The normal `test` task retains upstream's JNI lifecycle
regression; supply `-Plibdatachannel.test-native-path=/absolute/built/library.so`
to run it against a focused binary from this checkout.

The public identity overload accepts paired certificate/key paths and an optional
private-key password. It uses upstream `rtcConfiguration` certificate fields;
explicit ICE configuration uses upstream `rtcSetLocalDescriptionEx`. An endpoint
can publish its fingerprint before allocating peers, then reuse that identity for
each peer. Private-key provisioning, trust and rotation remain caller policy.
The old no-identity API still uses native-generated certificates.

`RawUdpMuxListener` callbacks receive Java-owned datagram copies on the native mux
thread. They must remain bounded and must not invoke native APIs or block. Handler
exceptions fail closed. Listener close waits for in-flight callbacks before JNI
references are released; close peers before the listener. Deferred replay copies
at most 2048 bytes into the libjuice queue bounded to 1024 requests, and re-enters
the current guard before native ICE. `stats()` reports processed datagrams,
rejections, live ICE agents and promoted tuples. `closeAndAwait(Duration)` returns
false on timeout without releasing ownership, so callers can retry safely.

From a clean committed tree, `scripts/package-development.sh [maven-directory]`
runs native and JVM regressions and writes an immutable local artifact under
`io.github.teamziax:libdatachannel-java:<native-version>.0-dev.<full-commit>`.
The classifier is `x86_64`. `provenance.json` records all three native-chain SHAs
and artifact hashes. This developer binary targets the current host's system
OpenSSL/ABI; it is not the normal portable dockcross release. Nothing is uploaded.
Always rebuild headers and JNI together after changing the pinned native version.
