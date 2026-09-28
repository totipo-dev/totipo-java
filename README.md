# totipo-java

Java implementation of the Totipo vault protocol.

This repository targets **Totipo Vault Format v1**, design revision **r15**.
Development currently uses an exact pinned snapshot of the moving `v1-pre-rc` profile,
documented in [SPEC_PIN.md](SPEC_PIN.md). Java implements the r15 baseline state model;
no optional `advisory-history` capability is claimed. The corpus contains 105 cases:
93 baseline and 12 conditional advisory-history cases. All remain hash-verified;
conditional cases are excluded from baseline consumers without JUnit skips.
Existing TOKEN wide-frontier folds and ordinary fitting-frontier DEVICE presentation/rename
are implemented. DEVICE wide-frontier folding and application CRUD APIs remain deferred.

## Toolchain

- Gradle 9.8.0, pinned by the checked-in Gradle Wrapper.
- JDK 25 is the default Nix shell and compiler toolchain JDK; Gradle runs on it.
- Core and storage-nio production Java is compiled with `--release 17` so the reusable library can
  remain compatible with Java 17 consumers, including the planned Android
  implementation boundary.
- Nix/direnv provide the local development environment.
- `platform-linux` explicitly uses the JDK 25 toolchain and `--release 25`.
- BC 1.86 is core's only external runtime dependency. JUnit and Jackson Core are test-only.

## Build

The Gradle Wrapper, Nix and Gradle lock files, and dependency-verification
metadata are checked in. A fresh clone can build directly without running
the bootstrap script.

With Nix:

```sh
nix develop --command ./gradlew build
```

Or with direnv:

```sh
direnv allow
./gradlew build
```

With JDK 25 already configured in `JAVA_HOME`, run `./gradlew build` directly. The first build
downloads the pinned Gradle distribution and dependencies if they are not cached.
Gradle toolchain auto-download is disabled; Nix/local JDK 25 supplies both compilers.

```sh
./gradlew clean test                              # whole build
./gradlew :core:clean :core:test                   # portable core only
./gradlew :storage-nio:test                       # portable NIO, no native access
./gradlew :platform-linux:test                    # Linux integration
./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test
```

## Bootstrap maintenance

`bootstrap-m0.sh` is retained for explicitly regenerating the repository's
bootstrap files. Run it in the development shell, for example with
`nix develop --command ./bootstrap-m0.sh`. The script:

1. writes `flake.lock` when Nix is available;
2. generates a Gradle 9.8.0 Wrapper;
3. verifies the Wrapper JAR against Gradle's published SHA-256;
4. writes Gradle dependency locks;
5. writes SHA-256 dependency-verification metadata; and
6. runs the build.

Review any generated changes before committing, especially
`gradle/verification-metadata.xml`: newly recorded checksums come from the
artifacts downloaded during bootstrap.

## Architecture and capabilities

- `core`: Java 17 wire/crypto/readers, immutable accepted snapshots, derived graph topology,
  complete TOKEN value evaluation, candidate/TOTP policy, provenance, snapshot-based writers,
  TOKEN-specific conflict confirmation, and filesystem-free binding/key-custody SPIs.
- `storage-nio`: Java 17 discovery, immutable synchronized-object publication, and strong
  VAULT creation/password replacement. Depends on core.
- `platform-linux`: Java 25 directory fsync, authoritative local VAULT binding, and private
  P-256 key custody. Depends on storage-nio → core. Native symbols: `open`, `fsync`, `close`.

Each discovery pass builds a fresh `AcceptedSnapshot`. An accepted supported TOKEN owns
its complete value. Disappeared or unauthenticatable objects are absent; missing parents
cannot supply ancestry. Restart reconstructs current evidence from synchronized objects.
Incomplete discovery and currently visible unscoped future evidence are diagnostics.
Ordinary use and authorship apply per-TOKEN checks; a routable opaque current TOKEN head
blocks the affected TOKEN. Equal-valued concurrent heads are unambiguous. Different
complete values require visible conflict confirmation; values are never field-merged.

Ordinary TOKEN authorship uses exactly the current heads in its selected accepted snapshot.
Later arrivals create normal concurrency and do not reparent, re-sign, or invalidate the
planned object. Conflict confirmation binds TOKEN identity, supported heads, complete
alternatives, desired value, and typed intent. A process-local per-TOKEN semantic observation
generation preserves sensitivity to relevant information learned then removed. Unrelated
TOKENs, DEVICE presentation, provenance, and diagnostics do not stale confirmation.

DEVICE rename uses the bound local identity and every current same-DEVICE supported head,
including presentation-inert rejected/unresolved heads. Only verified current heads supply
authenticated names; differing names are conflicted, equal names remain unambiguous.
Opaque current DEVICE heads make presentation incomplete and block v1 rename (§49),
without changing TOKEN validity or credential generation. A rename captures one accepted
snapshot; late branches create normal concurrency. Frontiers exceeding the conservative
one-object capacity return `FOLD_REQUIRED`; DEVICE folding is deferred to M3.4b.
The rejected-head and future-DEVICE baseline cases now exercise presentation evaluation
and production rename/publication or its opaque-head rejection, with independent reader checks.
Unambiguous TOMBSTONE-to-LIVE restoration requires explicit restoration intent.

Writers validate typed inputs, encode canonically, sign once, encrypt, compute OBJECT_ID,
and publish. The signing boundary checks canonical DER and verifies the returned signature.
Writer-reader round trips are conformance tests. Acknowledged publication adds typed evidence
to the in-memory snapshot; ambiguous failure does not. Discovery or a later retry remains
permitted. First-TOKEN setup success requires matching valid self-signed DEVICE and TOKEN
publication acknowledgements; no advertised/success bit is persisted.

## Storage and durability

Synchronized storage is unreliable transport: contents may be malformed, stale, conflicting,
missing, replaced, or withheld. Local execution and same-privilege processes are trusted.
`NioDiscoverySource` reads exact direct-child names in `objects-v1`, bounded to 1025 bytes.
Observed symlinks and special files are excluded. Discovery needs no native access.

`V1ObjectPublicationStore.publish` never overwrites an existing object. An ordinary regular
canonical target containing exactly the intended 1024 bytes returns `ALREADY_PRESENT_EXACT`
without existing-file fsync, directory fsync, or a second read. New objects use a complete
same-directory named temp, file force, no-replace hard link, and directory fsync as reliability
hardening. Acknowledgement makes no global synchronization durability claim.

`StorageDurability` exposes only `syncDirectory(Path)`. Applications explicitly compose
`NioVaultBootstrapStorage.open(root, LinuxDurability.open())` and
`NioV1ObjectPublicationStore.open(root, LinuxDurability.open())`. There is no default no-op
capability, provider registry, or automatic platform selection.

VAULT identity and private-key custody retain strong local durability. Canonical VAULT
creation and password rewrap use complete forced staging, atomic install/replace, and
containing-directory fsync. Core authenticates staged and final bootstrap bytes and requires
the same root. Password rewrap does not revoke older bootstrap copies.

`LinuxVaultBindingStore` stores exactly 32 bytes in `vault-binding-v1.bin`, independently of
synchronized storage. After canonical VAULT authentication, absent binding is durably created;
a present binding must match exactly. Malformed data is an explicit corrupt anchor, never
absence. Creation forces an owner-only temporary file, installs without replacement, and
syncs its directory. There is no intermediate establishment transaction or graph journal.
This is a development-format break: r14 local journal migration is intentionally unsupported.
Synchronized protocol bytes are unchanged.

`LinuxDeviceProvenanceKeyStore` keeps an immutable owner-only P-256 record outside
synchronized storage. Private staging, force, no-replace installation, directory fsync,
exact vault binding and key validation remain. Group/other permissions are rejected.
Custody is exportable filesystem storage, not hardware-backed storage.

Temporary names are nonauthoritative; cleanup is best effort and a crash can leave residue.
Native durability supports reviewed Linux amd64/x86-64 libc. Writers grant native access
with `--enable-native-access=ALL-UNNAMED`; tests additionally deny implicit native access.
Core and storage-nio need no native access. Unsupported hard links/atomic moves fail without
fallback. Local crash durability requires filesystems/devices honoring force/fsync; process-halt
tests exercise restart behavior, not physical power loss.

## Remaining boundaries

BC 1.86 is the only external production dependency. Existing TOKEN wide-frontier folds use
ordinary immutable TOKEN stages with one complete value and common AUTHOR_TIME. They reduce
frontier width without deleting or compacting history. Ordinary folds retain their planning
snapshot; confirmed folds require renewed confirmation for new TOKEN-relevant information
under r15 §47.4. Interrupted stages remain ordinary history, with no journal or rollback.
DEVICE wide-frontier folding, alternate-bootstrap recovery, Android platform integration
and application APIs remain deferred. DEVICE presentation, fitting-frontier rename,
graph topology and current key material are implemented. Cross-run advisory history and rollback/regression warnings are
not implemented or required by baseline r15. No cross-run TOKEN/DEVICE/head/opaque cache exists.

The single r15 corpus is under `core/src/test/resources/totipo-spec`; production JARs contain
no corpus. `SPEC_PIN.md` is the repository-wide pin authority. DEVICE graph vectors use
symbolic accepted input evidence and real signed rename output; byte-level crypto/routing
fixtures and Linux discovery tests separately cover authenticated input classification.
Temporary unresolved DEVICE provenance is exercised at the semantic boundary.
