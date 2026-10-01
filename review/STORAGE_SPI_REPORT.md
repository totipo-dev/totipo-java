# Storage SPI implementation report

## Baseline

Starting HEAD: `5c5e799bd6cbe7dce5ef46f9caaf159f62f9f378`.
`git status --porcelain` was empty before work and remained empty after the
baseline build. No code was changed until the baseline completed.

Baseline command: `./gradlew clean build`, successful in 1m 55s, 22 tasks
executed. JUnit XML reported **364 tests: 306 core, 58 storage-nio**, with no
failures, errors or skips. `Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping`
passed: it executes and accounts for all **90/90 r17 cases**, asserting the
per-category inventory as well as the total.

Production Java LOC: **3,508**, counted as physical lines (including comments
and blanks) across `core/src/main/java` and `storage-nio/src/main/java`.
Tests, fixtures, generated sources and documentation are excluded.

Dependencies and target at baseline, unchanged at completion:

* Core production: Bouncy Castle `bcprov-jdk18on:1.86` for lightweight Argon2id;
  remaining crypto uses JDK providers.
* storage-nio production: API dependency on core, with no additional external
  production library.
* Tests: JUnit Jupiter/Platform/BOM 6.1.3; Jackson core/BOM 2.18.2 in core.
  Locked test support includes apiguardian-api 1.1.2, jspecify 1.0.0 and
  opentest4j 1.3.0. Existing core tests also use storage-nio and its test fixtures.
* Both modules use `--release 17`. Build verification checks every production
  class for non-preview Java 17 bytecode (major 61).
* Java 25 build toolchain; Gradle wrapper 9.8.0. No catalog, lock, verification
  metadata, wrapper, toolchain or build configuration changes.

## SPI types

The following new provider-facing top-level types are all in `dev.totipo.spi`:

| Type | Exact role and variants |
| --- | --- |
| TotipoStore | Cohesive synchronous read/scan/publication/preparation and close boundary |
| ObjectName | Exact opaque direct-child namespace name, no protocol grammar |
| ObjectEntry | Name, no-follow observed kind, OptionalLong logical content length |
| EntryKind | REGULAR, DIRECTORY, SYMLINK, OTHER, UNKNOWN |
| ObjectScan | Complete(entries), Incomplete(entries, reason); defensive unique-name lists |
| BoundedRead | Present(bytes), Undersized(observedLength), Oversized, Absent, WrongKind(kind), Unavailable(reason) |
| ObjectWrite | Written, AlreadyPresentExact, ExistingDifferent, Failed(reason), Uncertain(reason) |
| VaultPrepare | Prepared(vault), Failed(reason); no canonical mutation |
| PreparedVault | Same-stage read-back, one install or replace attempt, abandonment/cleanup |
| VaultInstall | Installed, AlreadyPresent, Failed(reason), Uncertain(reason) |
| VaultReplace | Replaced, Failed(reason), Uncertain(reason); deliberately no stale variant |
| StoreFailure | UNAVAILABLE, UNSAFE_NAMESPACE, UNSUPPORTED |

The package is explicitly experimental and not frozen for third-party source or
binary compatibility. `SPI_DESIGN.md` is the implemented boundary description,
not an addition to the wire specification.

The new integration entry point `dev.totipo.Totipo` accepts a TotipoStore.
`dev.totipo.storage.nio.NioTotipoStore` is the public NIO implementation.
Ordinary applications continue to use NioTotipo and VaultSession.

## Boundary

> The storage provider understands the Totipo storage layout, not the Totipo protocol.

Provider knowledge is limited to root, canonical lowercase vault, objects-v1,
exact direct-child names, entry storage kinds, optional logical content lengths,
bounded exact reads, opaque immutable publication, noncanonical staging,
canonical installation/replacement and configured durability acknowledgement.

Core alone understands TokenId, RevisionId, VaultFingerprint meaning, K_root,
password authentication, ObjectId and canonical object filename grammar,
envelope authentication, TOKEN format, parents/heads, graph/fold,
merge/conflict semantics, TOTP, freshness/rollback policy, authorization and sync.

The SPI and the new NIO engines have no application-domain or crypto imports,
and no hard-coded v1 record lengths. Protocol-sized adaptation is in core.
Legacy NIO adapters retain their former protocol signatures only for existing
low-level users/tests.

## Read semantics

ObjectName preserves the exact string. NIO checks only whether it safely names
one direct child; it does not reject junk or uppercase names as noncanonical
Totipo names. Enumerated names are the actual directory-entry spellings.
Case and normalization distinctions are retained. Lists cannot contain duplicate
exact names. Provider collection and public scan validation use exact-string
sorting and adjacent duplicate checks, not name-keyed hash tables. NIO retains
one observation of an anomalous duplicate and marks the result incomplete;
public ObjectScan constructors reject duplicate provider output.

ObjectScan enumerates every observed direct child, including directories,
symlinks, socket/other entries, temporary names and junk. EntryKind and logical
contentLength are observations, not pinned state. Metadata failure keeps an
UNKNOWN entry and makes the scan incomplete; interrupted enumeration retains
already-seen entries. No unrelated filesystem metadata crosses the boundary.

Entry kind and content length are observations from the scan, not authoritative
filters for later object reads. Core recognizes canonical-looking names before
creating candidates and freshly reads every such name, regardless of scan-time
kind. Fresh WrongKind contributes the existing unavailable-object evidence;
fresh Present can be validated normally. Noncanonical junk is not read.

Complete means the enumeration attempt reached its end safely, not an atomic
snapshot or freshness claim. Incomplete propagates to the existing core
discovery diagnostics, preserving the distinction needed by merge freshness.
Observed valid objects still contribute to ordinary projection. Positively
absent objects-v1 maps to Complete(empty), with no creation; unsafe/unavailable
namespaces are Incomplete. Alias lookup never selects a canonical namespace.

readObject takes ObjectName, not ObjectEntry, and freshly resolves the actual
exact name. readVault does the same for lowercase vault. Both reobserve kind and
content, without trusting scan size/kind. NIO checks NOFOLLOW_LINKS attributes
and opens content without following the final link.

Reads consume at most expectedBytes + 1 bytes. The implementation reads the
bounded candidate then one extra byte separately, including at Integer.MAX_VALUE,
without using metadata to infer EOF or oversize. Present requires complete
exact-sized bytes; short EOF, extra byte, proved absence, nonregular kind and
unavailable observation remain separate outcomes. Present arrays are defensive
copies. Read races may report Unavailable rather than falsely prove absence.

The core adapter maps size-only invalid results to invalid-length bounded
streams for the proven legacy readers, retaining invalid-format/invalid-storage
taxonomy. It never fabricates a valid protocol record. It alone filters
canonical object-name grammar and requests the v1 sizes.

## Object publication

Written acknowledges a newly installed exact child. AlreadyPresentExact
acknowledges both equality and required durability, allowing recovery from an
earlier uncertain install. ExistingDifferent reports unequal existing bytes
without replacement. Failed proves no exact-target change by this invocation;
Uncertain admits possible mutation without acknowledged persistence.

The shared NIO engine snapshots caller bytes and ensures an exact safe objects-v1
namespace. For every new object publication it positively acknowledges the root
directory before staging/target mutation, including when reopening an existing
namespace. This stateless rule replaces process-local pending-sync knowledge.
It then creates and forces staging, installs with a no-replace hard link, and
performs file/directory durability work. New SPI writes also confirm exact stored-name visibility.
Existing-different bytes are never overwritten. Case-alias collisions never
become exact-existing success.

The SPI path retains and strengthens the application's exact-existing barrier:
force the regular file, force objects-v1 and root, then confirm bytes again.
Failure at any of these acknowledgement steps cannot report success. Legacy
V1ObjectPublicationStore retains its original read-only exact-existing contract;
its application wrapper and the SPI use the shared stronger acknowledgement
path. There are no independent publication implementations.

Bytes remain caller-owned; the provider neither mutates nor retains the caller
array. Provider code does not interpret byte contents or derive identities.

## Vault staging

prepareVault writes and forces a separate provider-owned temporary representation.
It does not change canonical vault; preparation failure remains definite even
if best-effort cleanup leaves a private artifact. Core re-reads the actual
representation and validates exact staged bytes before mutation.

readBack uses fresh BoundedRead outcomes. Install and replace use that same
representation, never a reconstructed candidate. The tests modify the actual
stage, read the changed bytes, and prove those are the bytes installed.

Install is no-replace, acknowledges durability, distinguishes exact canonical
presence from an alias collision, and never overwrites an existing vault.
Replace has no BASE argument or stale meaning. Core retains authentication,
root preservation, fresh CURRENT read, exact BASE comparison and lifecycle
taxonomy.

One mutation attempt consumes the handle, including failed or already-present
attempts. Subsequent read/mutation is a lifecycle error. Close is idempotent and
best-effort, cleans only staging and never rolls back canonical state. Store
close abandons outstanding stages. Cleanup failure does not downgrade a
successful canonical acknowledgement.

The SPI requires neither atomic move nor CAS. NIO tries atomic replacement
and falls back to a regular replacement move on AtomicMoveNotSupportedException.
The legacy low-level adapter still requires atomic replacement for its existing
callers. Tests exercise the actual SPI fallback and a weaker provider's partial
replacement failure; the latter is Uncertain with no rollback.

## Persistence certainty

Failed requires positive evidence of no canonical target mutation by this
invocation. It is not inferred merely from an exception. NIO tracks mutation
entry before link/move. Pre-mutation staging/barrier/precondition failures and
proved exclusive-link collisions remain definite; errors after possible
mutation become Uncertain.

For new object publication, root-sync precedes staging and exclusive-link entry.
Root-sync failure therefore returns Failed with no object-target mutation by
this invocation. The mutation boundary is immediately before the link operation;
errors after it are Uncertain unless a definite no-effect collision is proved.
The stronger exact-existing recovery barrier remains unchanged.

One shared NioNamespace helper classifies positively observed structural hazards
as UNSAFE_NAMESPACE (unsafe directory components, nonregular publication targets,
or unresolved alias collisions). Ordinary I/O failure remains UNAVAILABLE, and
unsupported operations remain UNSUPPORTED. A concurrent exact namespace creation
is rechecked before inferring an alias. Fresh nonregular reads retain WrongKind.

Exact-existing retry barrier failures stay uncertain until all required
acknowledgements succeed. Core conservatively treats unexpected runtime
exceptions after publication/install/replace entry as uncertain.

Application publication retains its existing monotonic policy: once publication
has been entered, even a later SPI Failed/ExistingDifferent outcome cannot
downgrade the frozen operation's uncertainty. Positive acknowledgements for
every object yield Saved. The new definite vault outcomes are translated
explicitly into Failed or AlreadyExists; ambiguous outcomes retain Uncertain.

These acknowledgements concern the configured provider only, not remote sync,
replication, peer observation, rollback resistance or universal physical
power-loss survival.

## Ownership

Totipo.open/create take ownership of a nonnull store for the call. Failure,
including invalid password input, closes it before returning/throwing. On
success VaultSession owns it until close. Callers must neither use nor close
the transferred store.

StoreAdapter owns the single store behind the legacy bootstrap/discovery/
publication views. Its idempotent close prevents the session's existing
multi-resource cleanup from closing the provider twice. Successful open/create,
failed open/create, repeated session close and staging cleanup failures are
tested through the SPI.

## Migration

The high-level path is now:

```text
NioTotipo -> NioTotipoStore -> Totipo -> ApplicationVaults store overload
    -> StoreAdapter -> existing application/protocol machinery -> VaultSession
```

ApplicationVaults is explicitly superseded as a provider bridge. Its older
three-interface overloads remain only for migration and existing low-level tests;
normal NIO applications no longer construct or pass those three capabilities.

DiscoverySource, V1ObjectPublicationStore, VaultBootstrapStorage and
VaultBootstrapReplacementStorage remain as proven internal machinery. StoreAdapter
translates the deliberate SPI onto them. The protocol implementation was not
broadly rewritten.

NioDiscoverySource, NioV1ObjectPublicationStore, NioApplicationPublication and
NioVaultBootstrapStorage now use shared engines: NioObjectScan,
NioObjectStorage and NioVaultStorage. NioReads supplies exact-sized SPI reads;
NioFiles retains shared NIO primitives. StorageDurability is unchanged.
The legacy protocol wrappers are not the new provider contract.

## NIO implementation

Construction checks the configured existing directory without creating vault,
objects-v1, temporary files or repairs. Namespace creation remains lazy until
explicit object publication. Exact selection enumerates actual child names and
compares Java strings; reconstructed paths and lookup aliases never establish
exact-existing identity. Final symlinks are not followed; traversal is direct.

The provider retains the established trusted local OS/filesystem/mount/process
namespace model. Metadata/read/mutation races are not CAS and no descriptor-pinned
snapshot is claimed. Atomic moves are opportunistic on the SPI path; uncertainty
is conservative for the weaker fallback.

## Tests and evidence before remediation

SPI introduction verification command: `./gradlew clean build`, **BUILD SUCCESSFUL in
1m 16s** (22 tasks: 17 executed, 4 from cache, 1 up-to-date). The core and
storage-nio test tasks both executed in that run. These counts are the
pre-remediation baseline; final remediation evidence appears below.

| Evidence | Baseline | Final |
| --- | ---: | ---: |
| Core tests | 306 | 337 |
| storage-nio tests | 58 | 108 |
| Total tests | 364 | 445 |
| Failures / errors / skips | 0 / 0 / 0 | 0 / 0 / 0 |
| Executed r17 corpus cases | 90/90 | 90/90 |
| Production Java physical LOC | 3,508 | 4,110 |

The **81 additive SPI tests** comprise 50 NioSpiTest executions and 31
SpiApplicationTest executions. They cover:

* Every direct-child kind/name, exact case and Unicode spelling, unique-name
  results, complete/partial enumeration, retained UNKNOWN metadata and
  reobservation after length/kind changes.
* Exact/short/one-byte-long/1 TiB sparse reads, missing targets, directory/link
  rejection, no recursive path escape, zero/MAX_VALUE bounds, defensive bytes.
* Opaque publication, immutable mismatch, alias collision, pre/post-mutation
  faults, file and directory retry barriers, exact retry and caller ownership.
* Private preparation, exact/short/long/missing/wrong-kind/unavailable staged
  reads, corrupt staged data rejected by core, abandonment and preparation failure.
* No-replace installation, exact presence versus aliases, definite failures,
  ambiguous acknowledgements and handle consumption.
* Same-stage replacement, successful non-atomic fallback, definite failure,
  partial ambiguous replacement, core stale comparison and unchecked exceptions.
* Read-only store opening, transferred-store cleanup, session lifetime,
  exactly-once close and harmless repeated application close.

All 364 pre-existing tests were retained unchanged in the SPI introduction,
including all facade and lower-level regressions. The remediation retains them
and updates one provider fault fixture to permit the newly required root barrier.
No corpus, specification, SPEC_PIN or API_DESIGN file changes.
`git diff --check` passes. The final HEAD remains the starting HEAD; the final
working tree intentionally contains the uncommitted SPI implementation,
additive tests, README update and the two requested documents.

The suite ran on the existing case-sensitive Linux local filesystem with hard
links, symlinks, directory force, sparse files and Unix-domain sockets available.
The existing suite also requires its previously documented POSIX/atomic-move
capabilities. No tests were skipped. Alias collisions and lost acknowledgements
are injected where the host cannot directly exhibit the condition. This is not
new qualification of case-insensitive filesystems, other operating systems,
remote providers or physical power-loss behavior.

Javadoc emits the repository's existing style of missing-comment warnings;
Java compilation remains under `-Xlint:all -Werror` and succeeds. No production
or test dependency was added.

## Deviations

No required architectural or semantic deviation. The explicitly permitted
incremental migration is used: the old bridge is clearly superseded rather
than deleted, and legacy interfaces/wrappers remain to preserve authoritative
tests and low-level contracts. The new SPI uses the requested conceptual names.

Handle consumption is deliberately stricter after definite failures as well:
every canonical mutation attempt consumes the handle, matching the one-attempt
rule. The old low-level atomic-only contract is preserved only in its adapter;
the deliberate SPI has no atomicity requirement.

## Open issues

No unresolved implementation issue from this phase. Long-term third-party SPI
compatibility remains intentionally unfrozen; provider/OS and physical durability
qualification beyond the documented test environment remains future work.

## Narrow SPI remediation

This pass starts from the uncommitted SPI implementation described above, at
the same HEAD `5c5e799bd6cbe7dce5ef46f9caaf159f62f9f378`. It addresses only
the four storage-boundary findings. All changes remain uncommitted. The
pre-existing `public-api-facade.patch` was left untouched.

### Files changed in this remediation

| File | Change |
| --- | --- |
| `core/src/main/java/dev/totipo/spi/ObjectScan.java` | Replace hostile-name HashSet validation with exact-string sorting and adjacent checks |
| `core/src/main/java/dev/totipo/format/StoreAdapter.java` | Retain every canonical-name candidate regardless of scan-time kind |
| `storage-nio/src/main/java/dev/totipo/storage/nio/NioObjectStorage.java` | Remove rootSyncPending; require a stateless root barrier for every new publication; classify alias collisions |
| `storage-nio/src/main/java/dev/totipo/storage/nio/NioObjectScan.java` | Replace LinkedHashMap collection with sort/deduplicate; share safety classification and recheck concurrently created exact namespaces |
| `storage-nio/src/main/java/dev/totipo/storage/nio/NioNamespace.java` | New package-private structural-safety classification helper, including an exclusive-create collision subtype |
| `storage-nio/src/main/java/dev/totipo/storage/nio/NioFiles.java` | Signal positively observed wrong directory/regular-entry structure through the shared helper |
| `storage-nio/src/main/java/dev/totipo/storage/nio/NioReads.java` | Use the shared failure classification |
| `storage-nio/src/test/java/dev/totipo/storage/nio/NioSpiTest.java` | Ordering/reopen, colliding-name and classification regressions; strengthen existing unsafe-reason assertions |
| `storage-nio/src/test/java/dev/totipo/storage/nio/NioExactNameTest.java` | Allow only the required root barrier in the existing exclusive-create collision fixture |
| `core/src/test/java/dev/totipo/api/SpiApplicationTest.java` | Exercise every scan kind through fresh reads and preserve junk-name filtering |
| `SPI_DESIGN.md` | Document stateless durability, comparison-based name validation, observational metadata and failure classification |
| `review/STORAGE_SPI_REPORT.md` | Update the implemented boundary description and record this remediation |

The legacy collision test previously asserted that no durability barrier could
occur before losing the exclusive-create race. It now permits the newly required
root barrier and still rejects any other directory barrier. All original test
methods and their identity/no-overwrite assertions remain.

### Stateless durability and exact mutation boundary

Every invocation that proceeds toward a new object installation establishes:

```text
observe/create exact safe objects-v1
    -> positively acknowledge root-directory durability
    -> write and force noncanonical object staging
    -> enter exclusive-link operation (object-target mutation boundary)
    -> force installed representation and objects-v1
    -> Written
```

There is no pending-root-sync flag or remembered namespace-durability state.
A directory surviving provider A's failed root acknowledgement cannot bypass
the root barrier when provider B opens. Failure at that barrier is Failed:
the invocation has not entered object-target mutation. This remains true even
when the directory was created by an earlier failed attempt.

The engine marks mutation entry immediately before the exclusive link. A lost
acknowledgement or other error after that point remains Uncertain unless a
definite exclusive-create collision proves this invocation had no target effect.
This pass does not widen Failed past the existing certainty boundary.

AlreadyPresentExact retains the file force, objects-v1 force, root force and
post-barrier byte confirmation. No exact-existing recovery barrier was removed.
Application publication code is unchanged: accumulated PublicationUncertain
cannot be downgraded by a later Failed retry and is resolved only by complete
positive acknowledgement.

The focused suite exposed a concurrent namespace-creation race while sharing
the namespace safety check: the exact child can appear between enumeration and
lookup. Rechecking its actual spelling before classifying an alias preserves
the existing concurrent-publisher behavior. No alias is accepted as an exact
winner.

### Hostile names, fresh reads and safety classification

Both public ObjectScan validation and NIO scan collection now use lists sorted
by exact Java String values and adjacent duplicate checks. Neither path uses a
name-keyed hash table. NIO retains the first observation of a duplicate and
returns Incomplete; public scan constructors reject duplicates. Case-distinct
and normalization-distinct names remain distinct.

The collision regression supplies 16,384 distinct combinations of Aa/BB, all
with equal String.hashCode(), through the provider enumeration fault seam and
the public scan constructors. One real metadata fixture supplies observational
attributes; the test does not require 16,384 filesystem allocations. It checks
sorted exact uniqueness and both duplicate failure paths without timing
assertions.

Entry kind and content length are observations from the scan, not authoritative
filters for later object reads. StoreAdapter recognizes canonical names, then
creates candidates for all kinds. WrongKind from the fresh read maps into the
existing unavailable-object evidence, preserving graph/current-state and
merge-freshness handling. A fresh valid Present is processed even after UNKNOWN
or nonregular scan metadata. Junk/noncanonical names remain unprobed.

NioNamespace is the shared internal classification mechanism; there is no
exception-message parsing. Positively known unsafe namespace structure and
alias collisions map to UNSAFE_NAMESPACE across scan/read/publication paths.
Ordinary inability to access or observe remains UNAVAILABLE. Freshly observed
nonregular read targets still return WrongKind, rather than erasing that
distinct read outcome. No NIO exception classes escape through SPI results.

### Exact new regression tests

In `NioSpiTest`:

* `reopenedProviderRequiresRootBarrierBeforeEveryNewObjectMutation`: A creates
  the namespace and fails root sync; after A closes, B also fails root sync
  with the object absent, then succeeds only after an acknowledged root barrier.
  The link fault seam asserts the precise preceding event sequence. A subsequent
  new name requires another root barrier; exact-existing recovery still succeeds.
  Open/scan/read calls produce no durability events.
* `collidingHostileNamesUseSortedScanValidationAndExactDuplicateChecks`:
  16,384 equal-hash names, exact sorted uniqueness, public constructor rejection,
  and incomplete deduplicated NIO output.
* `namespaceCreationAliasCollisionIsUnsafe`: an alias collision during namespace
  creation returns Failed(UNSAFE_NAMESPACE), without a mutation barrier.
* `structurallyBlockedObjectPublicationIsUnsafe` (2 cases): directory and
  symlink object targets preserve scan kind and fresh WrongKind, while publication
  returns Failed(UNSAFE_NAMESPACE).
* `rootSafetyAndOrdinaryUnavailabilityRemainDistinct` (2 cases): a replaced
  non-directory root is unsafe; an unavailable/missing root remains unavailable,
  consistently across scan, vault read, object read and publication.

Existing `unsafeNamespaceNeverLooksEmpty` (file/symlink namespace) and
`aliasCollisionIsNeverExactExisting` now assert exact StoreFailure reasons.
Existing exact-existing barrier/retry tests remain intact.

In `SpiApplicationTest`:

* `everyCanonicalScanKindGetsFreshReadAndWrongKindEvidence` (5 cases):
  every EntryKind becomes a candidate; fresh WrongKind yields an UNAVAILABLE
  diagnostic rather than silent absence. REGULAR-to-SYMLINK change is included;
  junk, temporary and wrong-length names are not read.
* `nonRegularScanKindCanBecomeValidAtFreshRead` (4 cases): SYMLINK, DIRECTORY,
  OTHER and UNKNOWN metadata all permit processing when the fresh read contains
  a valid object. Junk is still not read.

### Final validation and scope

| Evidence | Before remediation | After remediation |
| --- | ---: | ---: |
| Production Java physical LOC | 4,110 | 4,140 |
| Core tests | 337 | 346 |
| storage-nio tests | 108 | 115 |
| Total tests | 445 | 461 |
| Failures / errors / skips | 0 / 0 / 0 | 0 / 0 / 0 |
| Executed r17 corpus cases | 90/90 | 90/90 |

There are 16 additional regression executions (9 core, 7 storage-nio). The
complete `./gradlew clean build` passed in **1m 19s**: 22 tasks, 16 executed
and 6 from cache. Both module test tasks executed, covering all facade,
provider/exact-name, previous hardening, graph/fold/codec/crypto and vault
lifecycle tests. The existing Java 17 bytecode checks and compilation under
`-Xlint:all -Werror` pass. Javadoc retains nonfatal missing-comment warnings.
`git diff --check` passes. Source inspection/search confirms no rootSyncPending
or hostile-name hash-table duplicate detection remains in the SPI scan path.

No corpus, specification, SPEC_PIN, API_DESIGN, dependency or build configuration
changed. No wire/protocol, crypto, TOKEN, graph/fold/merge, public application API,
state-stream, ownership-transfer or accumulated persistence-certainty semantics
changed. This restores the intended storage acknowledgement and observational
metadata contracts. Construction and observation remain side-effect-free.
Staged VAULT implementation and its mutation/lifetime rules are unchanged,
apart from the explicitly permitted shared error classification. No atomic-move
or CAS requirement was added.
