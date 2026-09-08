# Contribution provenance

This maintained fork compares `nxs-dev` with the upstream mirror at `b31809f14e0d8d62d4c800902e03b4108d95529d`.
The aggregate owned draft records the combined work; future external submissions
should separate independent fixes, acceptance APIs and lifecycle changes.

| Source | Contribution |
| --- | --- |
| Upstream [`b31809f1`](https://github.com/pschichtel/libdatachannel-java/commit/b31809f14e0d8d62d4c800902e03b4108d95529d) | Baseline with thread attachment, unload synchronization, callback lifetime fixes and regression tests. |
| Zulu `39ec8c6`, `70efb59` | Original identity, ICE, packet-callback and local packaging work. Application-specific probes moved downstream with attribution. |
| Zulu `0812c7e`, `5544964`, `7885652` | Cleanup completion, callback-context checks and callback detachment. |
| Zulu `4a12f67`, `40f2c32` | Earlier deferred packet handling and limits, now replaced by native-owned pending requests. |
| Merge commits `97268df`, `66014e1` | History only; no duplicate patches. |
| Consolidation and current changes | Public C API use, asynchronous metadata callbacks, retained failure ownership, native log filtering, encrypted PEM support and generic regressions. |

## Review follow-up, 8 September 2026

Settle waiting-request cancellation independently of the application executor, bind authenticated peer reuse and asynchronous destruction, add named statistics and an acceptance builder with shared identity configuration, retain compatibility adapters, and move construction diagnostics out of the public Java API.
