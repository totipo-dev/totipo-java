# Totipo Java

Portable Java libraries targeting Totipo Vault Format v1, revision **r16**.
The exact committed specification and language-neutral corpus are pinned in
[SPEC_PIN.md](SPEC_PIN.md).

This repository is in a staged r16 migration. Phase 3 adds pure causal graph/state
evaluation and fixed linear-carry fold construction to the exact TOKEN codec.
Consumers cover all 69 bootstrap, crypto, encoding, fold, graph, metadata, size,
and TOTP cases. Authorship/publication orchestration and storage/vault workflow
reconciliation remain deferred.
Snapshot/profile integrity tests separately verify all 90 target cases. There is no full Java API stability
promise yet; most core implementation types remain package-private.

The two production modules are:

- `core`: portable Java 17 Totipo primitives and protocol foundation: bootstrap and
  Argon2id, root/object crypto, private keyed object identity, authenticated fixed
  envelopes, exact TOKEN semantics and TLV codec, causal groups and current heads,
  deterministic fold construction, password handling, Java credential values, TOTP, entropy,
  and storage observation/publication/bootstrap SPIs.
- `storage-nio`: portable Java 17 configured-store filesystem implementation:
  direct-child discovery, immutable object publication, bootstrap storage, and an
  injectable directory durability capability. It depends on `core`.

`core` depends on Bouncy Castle `bcprov` for lightweight Argon2id. Other crypto uses
JDK providers. Jackson and JUnit are test-only. Both modules compile with
`--release 17`, and build checks inspect every production class for Java 17 bytecode.
The build JVM/toolchain remains JDK 25; the Gradle wrapper, dependency locks, and
verification metadata remain pinned. No Linux-native module is currently required.

Build and test with the repository wrapper in the existing Nix development shell
(`nix develop`, or `direnv allow`), or with JDK 25 available:

```sh
./gradlew clean test build
./gradlew :core:test
./gradlew :storage-nio:test
./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test
```

Directory durability is attempted using `NioDurability` and pure Java NIO.
`NioDurability` is a pure-Java runtime capability. Successful return means the
provider accepted the requested directory-channel force operation; unsupported
providers fail rather than being treated as durable. Java SE does not guarantee
directory fsync semantics on every provider. `StorageDurability` stays injectable
for a future supported backend if needed. No native-access JVM flags are required.

Discovery observes the configured root and exact `objects-v1` directory without
following final symlinks, considers only direct canonical lowercase-hex regular
files, and reports namespace/enumeration issues diagnostically. Candidate bytes
are hostile; bounded reading and envelope authentication remain separate primitives.
A snapshot implies no global operation gate.

Storage mechanics are retained for later r16 lifecycle reconciliation. Object
installation still uses the existing hard-link algorithm, and bootstrap replacement
still uses the existing atomic-move mechanism. Exact BASE comparison and r16 vault
creation/open/rewrap orchestration belong to Phase 5. These mechanisms do not yet
constitute full r16 storage/workflow conformance.

The test snapshot is under `core/src/test/resources/totipo-spec/v1-pre-rc/` and is
excluded from production JARs. Java derives behavior from the normative
specification and language-neutral corpus, not from the Go implementation.
See [R16_PHASE1_RECONCILIATION_REPORT.md](R16_PHASE1_RECONCILIATION_REPORT.md) for
validation, deletions, and remaining phases. See
[R16_PHASE2_TOKEN_CODEC_REPORT.md](R16_PHASE2_TOKEN_CODEC_REPORT.md) for exact codec
coverage, validation evidence, and the Phase 3 boundary.
See [R16_PHASE3_GRAPH_FOLD_REPORT.md](R16_PHASE3_GRAPH_FOLD_REPORT.md) for graph/fold
semantics, corpus coverage, validation evidence, and the Phase 4 boundary.

To intentionally refresh build reproducibility inputs, use `bootstrap-m0.sh` and
review the resulting wrapper, Nix lock, module dependency locks, and verification
metadata changes. Normal builds do not regenerate specification vectors.
