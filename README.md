# Totipo Java

Portable Java libraries targeting Totipo Vault Format v1, revision **r17**.
The exact committed specification and language-neutral corpus are pinned in
[SPEC_PIN.md](SPEC_PIN.md).

Normal Java clients should start with `NioTotipo.open(path, password)` or
`NioTotipo.create(path, password)` in `org.totipo.storage.nio`, then use the
`org.totipo` application API: `VaultSession`, immutable `VaultState` projections,
create/update/merge builders and session-backed TOTP. The directory must already
exist. These entry points and saves may block; inspect their explicit lifecycle
and persistence results. See [API_DESIGN.md](API_DESIGN.md) for the contracts and
[facade implementation evidence](review/PUBLIC_API_FACADE_REPORT.md) for coverage.
Provider integrations use the deliberate `org.totipo.spi` boundary, implemented
by `NioTotipoStore`. This SPI is experimental, not frozen for source/binary
compatibility. Providers understand only storage layout and storage semantics;
protocol interpretation stays in core. Ordinary applications need no SPI types.
See [SPI_DESIGN.md](SPI_DESIGN.md) for the boundary and ownership contract.

This repository has completed the r17 portable core implementation milestone:
**90/90 portable corpus cases implemented, none deferred**. The TOKEN codec,
graph/fold, TOKEN storage/authorship/publication, and VAULT lifecycle are complete
for this corpus. Configured-store observation validates TOKENs
for explicit graph evaluation; authorship planning uses caller-selected parents,
complete values, and exact metadata. Immutable publication executes ordinary or
linear-carry fold plans with safe explicit retries.
Consumers cover bootstrap, crypto, encoding, fold, graph, metadata, size,
storage, TOTP, and all eight vault workflow cases.
Implementation evidence is executable in
[Phase2ConformanceTest](core/src/test/java/org/totipo/format/Phase2ConformanceTest.java).
Snapshot/profile integrity tests separately verify all 90 target cases. There is no full Java API stability
promise yet; most core implementation types remain package-private. Corpus completion
is not the end of API design or implementation hardening, and does not establish
desktop/Android readiness or an independent production security audit.
Independent interoperability has not yet been demonstrated, and this milestone
does not claim release readiness. NIO provider qualification is limited to the
local case-sensitive Linux filesystem tested here; exact canonical naming and
the required operation capabilities must be qualified on each target provider.

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

The complete local integration suite assumes a case-sensitive filesystem, symlink
and hard-link support, atomic moves over existing targets where tested, directory
channels accepting force, POSIX permissions, and `mkfifo` for POSIX fixtures.
These are test-environment assumptions, not all protocol requirements. Some
provider integration fixtures report unsupported capabilities through JUnit
assumptions; the normative 90-case conformance inventory must still execute
90/90 without skips. Portable semantic conformance and provider integration
evidence are separate: case-sensitive-host tests do not qualify case-insensitive
providers. Windows, macOS, Android, and physical crash/power-loss behavior remain
unqualified by this suite.

Directory durability is attempted using `NioDurability` and pure Java NIO.
`NioDurability` is a pure-Java runtime capability. Successful return means the
provider accepted the requested directory-channel force operation; unsupported
providers fail rather than being treated as durable. Java SE does not guarantee
directory fsync semantics on every provider. `StorageDurability` stays injectable
for a future supported backend if needed. No native-access JVM flags are required.

Provider scans expose all observed direct children of the exact `objects-v1`
directory, with no-follow kind and optional logical length observations. Core
selects canonical lowercase-hex regular candidates and reports namespace/enumeration
issues diagnostically. Candidate bytes
are hostile; the TOKEN reader composes bounded reads, envelope authentication, and
exact grammar validation. Diagnostics preserve independently valid observations
and imply no global operation gate. Valid bytes do not certify the observed set
or its freshness. Graph evaluation explicitly consumes the validated subset.
Canonical namespace, existing object, and `vault` lookups select exact observed
direct-child directory-entry spellings. Alternate-case siblings are ignored;
provider alias collisions during no-replace creation fail conservatively.

TOKEN and initial VAULT installation use no-replace hard links. The SPI NIO provider
attempts atomic replacement, falling back to a non-atomic move when atomic move is
unsupported; the legacy low-level adapter retains its atomic-only contract. VAULT workflows
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

To intentionally refresh build reproducibility inputs, use `bootstrap-m0.sh` and
review the resulting wrapper, Nix lock, module dependency locks, and verification
metadata changes. Normal builds do not regenerate specification vectors.

## Maven consumption (release preparation)

Java implementation release **0.1.0 is being prepared and is not claimed to be
available on Maven Central**. After the operator publishes it, normal applications
can use Maven Central and:

```kotlin
implementation("org.totipo:totipo-storage-nio:0.1.0")
```

`totipo-storage-nio` is the normal filesystem/NIO entry point and provider. It
exposes `totipo-core` transitively, including `VaultSession` and `VaultState`.
Use `NioTotipo` and the high-level application API; the SPI guidance above remains
unchanged. For portable protocol/application API and core implementation without
an NIO provider:

```kotlin
implementation("org.totipo:totipo-core:0.1.0")
```

Core brings Bouncy Castle 1.86 at runtime for Argon2id, without exposing BC as a
public compile dependency. Both artifacts require Java 17; tests, test fixtures,
and the specification snapshot are excluded from publications.

`VERSION` is the single implementation version source. Protocol compatibility is
separate: 0.1.0 implements v1/r17. Future bug-fix releases can continue to implement
v1/r17, and later specification revisions do not mechanically dictate Java semantic
versions. See [the release checklist](RELEASE_CHECKLIST.md) for exact provenance,
credential-free Maven consumer verification, signing, and the manual Central gates.
The [J1.1 namespace migration report](review/J1_1_NAMESPACE_MIGRATION_REPORT.md)
records the current release identity and supersedes J1 coordinates for release readiness.
Publication checks additionally require Python 3.9+ (standard library only).
