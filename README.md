# Totipo Java

Portable Java libraries targeting Totipo Vault Format v1, revision **r17**.
The exact committed specification and language-neutral corpus are pinned in
[SPEC_PIN.md](SPEC_PIN.md).

This repository has completed the r17 portable core implementation milestone:
**90/90 portable corpus cases implemented, none deferred**. The TOKEN codec,
graph/fold, TOKEN storage/authorship/publication, and VAULT lifecycle are complete
for this corpus. Configured-store observation validates TOKENs
for explicit graph evaluation; authorship planning uses caller-selected parents,
complete values, and exact metadata. Immutable publication executes ordinary or
linear-carry fold plans with safe explicit retries.
Consumers cover bootstrap, crypto, encoding, fold, graph, metadata, size,
storage, TOTP, and all eight vault workflow cases.
See [R17_PHASE5_VAULT_REPORT.md](R17_PHASE5_VAULT_REPORT.md)
for implementation and validation evidence.
Snapshot/profile integrity tests separately verify all 90 target cases. There is no full Java API stability
promise yet; most core implementation types remain package-private. Corpus completion
is not the end of API design or implementation hardening, and does not establish
desktop/Android readiness or an independent production security audit.

The two production modules are:

- `core`: portable Java 17 Totipo primitives and protocol foundation: bootstrap and
  Argon2id, root/object crypto, private keyed object identity, authenticated fixed
  envelopes, exact TOKEN semantics and TLV codec, causal groups and current heads,
  deterministic fold construction, password handling, Java credential values, TOTP, entropy,
  configured-store TOKEN observation and authorship planning/publication,
  VAULT creation/open/password rewrap, and storage observation/publication/bootstrap SPIs.
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
are hostile; the TOKEN reader composes bounded reads, envelope authentication, and
exact grammar validation. Diagnostics preserve independently valid observations
and imply no global operation gate. Valid bytes do not certify the observed set
or its freshness. Graph evaluation explicitly consumes the validated subset.

TOKEN and initial VAULT installation use no-replace hard links; bootstrap replacement
uses an atomic move and fails if the provider cannot support it. VAULT workflows
open only lowercase `vault`, read at most 88 bytes, authenticate complete candidates
and their separate stages, and preserve the exact root across password changes.
Replacement re-observes canonical bytes and requires exact equality with authenticated
BASE immediately before the backend attempt. This is compare-before-replace, not
atomic CAS; the remaining race is an explicit v1 limitation. Ambiguous acknowledgements
never report success or trigger automatic rollback/retry. Orphan TOKEN files do not
block creation, and rewrap does not inspect or rewrite TOKENs.

The vault fingerprint recognizes a root; it proves neither freshness nor authorization.
No remembered fingerprint is required to open. A saved old wrapper and its password
can still recover the root after rewrap; v1 does not provide rollback protection.
Tests exercise force operations, close/reopen persistence, and injected failures,
not universal physical power-loss guarantees.

TOKEN publication acknowledges
the local configured store only; it implies no remote propagation. Plans retain
neither roots nor canonical plaintext. Caller parents may be unavailable; duplicate
parent input is rejected. Partial fold publication remains ordinary immutable
history, and the same plan can be retried explicitly after failure.

The test snapshot is under `core/src/test/resources/totipo-spec/v1-pre-rc/` and is
excluded from production JARs. Java derives behavior from the normative
specification and language-neutral corpus, not from the Go implementation.
Historical r16 migration reports: see [R16_PHASE1_RECONCILIATION_REPORT.md](R16_PHASE1_RECONCILIATION_REPORT.md) for
validation, deletions, and remaining phases. See
[R16_PHASE2_TOKEN_CODEC_REPORT.md](R16_PHASE2_TOKEN_CODEC_REPORT.md) for exact codec
coverage, validation evidence, and the Phase 3 boundary.
See [R16_PHASE3_GRAPH_FOLD_REPORT.md](R16_PHASE3_GRAPH_FOLD_REPORT.md) for graph/fold
semantics, corpus coverage, validation evidence, and the Phase 4 boundary.

To intentionally refresh build reproducibility inputs, use `bootstrap-m0.sh` and
review the resulting wrapper, Nix lock, module dependency locks, and verification
metadata changes. Normal builds do not regenerate specification vectors.
