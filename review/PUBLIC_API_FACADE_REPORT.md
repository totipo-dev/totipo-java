# Public application API facade implementation report

## Baseline and final comparison

Starting and final HEAD: `57cbe2be9860cd006ee5087203ccf8c50c1034fc`.
No commit was made. The initial working tree was clean (no uncommitted or
untracked files). Final changes are intentionally left for review.

Final working tree: 46 new files and two modified files (`README.md` and the
package-private `SecurityBytes` wipe hook); no deleted files or unrelated changes.

| Measure | Before | After |
| --- | ---: | ---: |
| Production Java physical LOC, including comments/blank lines | 2,288 | 3,508 |
| Core JUnit executions | 256 | 306 |
| storage-nio JUnit executions | 56 | 58 |
| Total JUnit executions | 312 | 364 |
| Failures / errors / skips | 0 / 0 / 0 | 0 / 0 / 0 |
| Application facade black-box tests | 0 | 50 |
| Additional NIO facade durability tests | 0 | 2 |
| r17 corpus cases exercised | 90 / 90 | 90 / 90 |
| External production dependencies | bcprov-jdk18on 1.86 | unchanged |
| Production target, both modules | Java 17, class major 61 | unchanged |
| Build JVM/toolchain | OpenJDK 25.0.4.1 | unchanged |

`storage-nio` still depends on `core`; BC is an implementation dependency of
core. Jackson 2.18.2 and JUnit 6.1.3 remain test-only. No build configuration,
dependency lock, verification metadata, specification or corpus file changed.
Production LOC counts `*.java` under both `src/main/java` trees with `wc -l`.

Baseline command: `./gradlew test` (both test tasks executed). Final verification:
`./gradlew test build`, including both Java-17-bytecode verification tasks, source
and Javadoc artifacts, and all existing test suites. Javadoc emits missing-comment
warnings, including existing internal APIs; compilation with `-Xlint:all -Werror`
and the build succeed. Test counts come from the generated JUnit XML totals.
`Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping` is one JUnit
execution that explicitly executes and asserts all 90 corpus cases; corpus counts
must not be mistaken for 90 extra JUnit executions. Snapshot/profile integrity
coverage also remains intact.

## Public API added

The ordinary package is `dev.totipo`. Every new top-level application type and its
role is listed below. Nested public variants are included explicitly.

| Type | Role |
| --- | --- |
| `VaultSession` | Live secret/storage owner, state observation, password change, close |
| `VaultState` | Immutable observed projection and same-session operation factories |
| `VaultFingerprint` | Session root recognition, lowercase hexadecimal value |
| `TokenId` | Logical token identity |
| `RevisionId` | Exact causal revision identity |
| `ClientMetadata` | Optional client name and unsigned-u64 time raw bits |
| `TokenStatus` | Active or tombstoned complete value |
| `TotpAlgorithm` | SHA1, SHA256, SHA512 selection |
| `TokenDescriptor` | Non-secret complete descriptive fields |
| `TokenState` | Token alternatives, heads, unresolved references and competition |
| `TokenAlternative` | Complete semantic equality class with opaque session value reference |
| `TokenHead` | Stable causal assertion and exact metadata |
| `UnresolvedReference` | Descriptive child/parent revision pair |
| `CompetingField<T>` / `CompetingField.Value<T>` | Grouped field value and carrying alternatives |
| `TokenCompetition` | Competition for every field, including secret equality |
| `CompetingSecret` | Secret equality classes |
| `SecretGroup` | Descriptive alternatives sharing a secret, without mutation capability |
| `ObservationProgress` | Progress without percentages |
| `ObservationProgress.Enumerating`, `.Processing`, `.Finished` | Permitted progress phases; Finished is local-only |
| `VaultDiagnostic` | Local observation diagnostic code |
| `TotpCode` | Code plus half-open deterministic validity interval |
| `NewSecret` | Defensive, closeable and redacted caller secret ingress |
| `TokenEditor<T>` | Shared fluent setter infrastructure, not a generic mutation operation |
| `CreateToken` | New logical token builder |
| `UpdateToken` | Explicit causal update builder |
| `MergeToken` | Selected-basis merge with agreed/unresolved/explicit fields |
| `MergeSecretChoice` | Exact-merge-owned secret selection capability |
| `PartialResolution` | Frozen original resolution, independent of builder lifetime |
| `PublicationRetry` | Independent exact-publication retry capability |
| `SaveResult` | Frozen-operation persistence knowledge |
| `PartialSaveResult` | Sealed subset excluding AdditionalConflict for partial save |
| `RetryResult` | Sealed subset permitting only Saved/PublicationUncertain for exact retry |
| `SaveResult.Saved`, `.AdditionalConflict`, `.Failed`, `.PublicationUncertain` | Explicit persistence and merge outcomes |
| `SaveResult.Reason` | Observation unavailable, unresolved fields, session closing, preparation failure |
| `OpenResult` | Read-only open outcome |
| `OpenResult.Opened`, `.Absent`, `.Unavailable`, `.InvalidVault`, `.AuthenticationFailed` | Separate observation/authentication outcomes |
| `CreateVaultResult` | Initial vault installation outcome |
| `CreateVaultResult.Created`, `.AlreadyExists`, `.Failed`, `.Uncertain` | Explicit initial creation certainty |
| `PasswordChangeResult` | Changed, authentication failed, stale, failed, uncertain |
| `SessionClosedException` | Consistent closed-session misuse exception |
| `dev.totipo.storage.nio.NioTotipo` | Ordinary `open(path, password)` / `create(path, password)` entry point |

## Internal bridges

`dev.totipo.format.ApplicationVaults` is one new public **provider/internal**
bridge because storage-nio must construct core sessions across the existing module
boundary. Application clients do not use it. It accepts the existing storage
boundaries and transfers ownership, including cleanup on unsuccessful opening.
Package-private `ApplicationSession` and `ApplicationStates` implement the facade
beside the existing package-private protocol implementation. No existing
package-private implementation class was made public or moved.

`SecurityBytes` gains only a package-private best-effort wipe method for values
owned by the facade. Codec, crypto, graph, fold, publication planning, internal
vault lifecycle and storage semantics remain unchanged. The facade reuses
bootstrap writer/unlocker and staging contracts to classify lifecycle certainty;
it cannot recover that distinction from the older mixed lifecycle enum alone.

Package-private `NioApplicationPublication` wraps the existing NIO store. Its
exact-existing acknowledgement additionally forces the file, object directory
and root before returning. This is needed for the stronger application Saved
contract after an earlier unacknowledged installation; r17's low-level exact-
existing read-only path remains unchanged. The bridge documents its provider
acknowledgement requirement. No general SPI redesign was attempted.

## State model

The session owns the root and a canonical map of decrypted complete TokenValues.
Each immutable alternative stores an opaque value key, non-secret descriptor and
captured immutable heads. Heads store immutable identity/metadata and an opaque
value key. No public state/projection/competition DTO contains raw secrets.
Redundant parsed secret copies are wiped after projection; unique observed values
are retained until close to support arbitrary historical references. Ingress
overrides are owned through session-registered builders and wiped on closure or
semantic freezing. JVM erasure remains best effort.

States retain immutable private causal identity facts, never graph evaluator
objects or filesystem resources. A hidden session-local sequence orders emissions;
projection operations never compare its age for validity. Old heads and
alternatives work with later states of the same session. Cross-session references
are rejected, including references from another opening of the same vault.

Provider observation/write coordination uses a provider gate; local secret access
and lifecycle use a separate local lock. Observation tasks are serialized on a
daemon executor. Current state is a volatile read of the
publisher's latest projection. Replay-latest subscribers have independent demand,
one scheduled drain each, a delivered-sequence watermark and no per-state queue.
Callbacks are serialized per subscriber on the common pool. onSubscribe always
precedes demand delivery; close completes with no later onNext. Ordinary
observation failures are diagnostics; fatal observation failures deterministically
close/error with the original cause. The first lifecycle termination wins races.
Callbacks hold neither session lock nor publisher monitor; reentrant close does
not wait for the invoking callback. See the remediation findings below.

## Mutation semantics

* Update(head): exactly the one supplied head.
* Update(alternative): all equal-valued current heads in the **receiving state**;
  if absent, exactly the supplied alternative's captured heads. Complete equality
  includes secret bytes. The session's later state is not substituted.
* Merge(TokenId): receiving state's complete current frontier.
* Merge(selected alternatives): exact union of selected captured heads, including
  historical/partial selection. Mixed tokens/sessions and empty input are rejected.

Distinct builders share setter infrastructure. Merge exposes competition, prefills
agreement, lists unresolved fields and permits arbitrary explicit new values.
Secret equality grouping is an intentional disclosure, documented prominently in
API_DESIGN.md. State SecretGroups are descriptive; mutation choices are bound to
one exact merge instance. No winner is chosen automatically.

## Merge freshness

M is the selected parent set; F0 is the entire receiving-state frontier, including
known heads intentionally omitted from M. Normal merge save performs fresh
observation, derives F1 and traverses original plus newly resolved same-token
ancestry from F0. A head of F1 outside that causal containment is newly relevant.
Equal-valued concurrent heads and advancing descendants therefore trigger
AdditionalConflict. Resolved ancestry already included by F0 does not. Traversal
never follows another logical token's ancestry, consistent with the existing
graph partition rules.

Insufficient observation produces definite `OBSERVATION_UNAVAILABLE` with no
publication. New relevant information produces AdditionalConflict, latest state
and an independent frozen original resolution. The original builder is terminal;
it is not rebased. Partial save skips further semantic gates and preserves M and
the original value/metadata. More information arriving before partial save does
not change that operation. Successful checking accepts the documented
check-to-publication race; it is not CAS, remote synchronization or freshness proof.

## Persistence certainty

Failed is definite non-entry into a potentially successful persistence point.
PublicationUncertain means the frozen operation may already have persisted;
Saved requires acknowledgements for every immutable stage. None implies remote
propagation or elimination of conflicts.

The existing publication SPI cannot identify all definite pre-write errors after
its method is entered, so the facade conservatively marks those outcomes
uncertain. Unresolved fields/preparation/unavailable merge observation can return
Failed before that boundary. Once uncertainty exists, failed retries stay uncertain
regardless of whether a later attempt wrote anything.

Freezing builds the existing deterministic fold plan and encrypts every stage
before publication. The retained operation consists of token identity and exact
encrypted stage bytes/identities; transient plaintext and copied secret are wiped.
Retries therefore preserve parents, value, metadata, fold stages and object
identities without semantic re-evaluation. Partial fold acknowledgement is not
mistaken for full success. Unchecked provider exceptions after mutation entry are
also treated conservatively, including bootstrap replacement/installation.

## Handle ownership

Builders stay editable through appropriate definite prepublication failures.
Saved/uncertain publication makes them terminal; AdditionalConflict also makes the
original merge terminal. Closing a builder cannot invalidate its independent
retry or partial-resolution handle.

Retry attempts transfer capability to their result: uncertainty yields a new
independent retry handle, while success consumes the old one. Closing a consumed
handle does not abandon its successor. Partial save likewise transfers capability
on uncertainty and never repeats AdditionalConflict. Closing a live handle
abandons the frozen operation, removes it from session ownership and releases its
retained ciphertext. Session close invalidates all capabilities, wipes unique
observed secrets and ingress overrides, and releases storage resources.

Close first sets the closing flag, rejecting new secret-backed entrants, then
releases the local lock and waits for the provider gate. Mutations already inside a provider call finish
with Saved/Uncertain semantics. Definitely prepublication work can return Failed.
The result of an already-uncertain operation is never downgraded by closure. Old
projections remain descriptively readable after resources and secrets are closed.

## Blocking and threading

Open/create, every builder save, partial save, exact retry, password change and
close may block for KDF, I/O or coordination and must not run on Swing EDT/Android
main thread. Setters/local crypto acquire only the local lock and do not wait for
the provider gate. TOTP does bounded local crypto and no configured-store I/O;
it supports explicitly selected
historical, conflicted and tombstoned alternatives. It reports the deterministic
half-open validity interval at the supplied nonnegative Instant.

state() and descriptive/competition accessors do no configured-store I/O;
requestRefresh is non-blocking and coalesces requests. Descriptive projections are
immutable/thread-safe for reads. Builders are thread-confined. Provider access and
emission are serialized per session; independent sessions/processes are not
serialized. Different subscribers may run concurrently, each with ordered callbacks.
No broader provider/platform thread-safety guarantee is made.

## Test evidence

50 application-facing tests use `dev.totipo` operations and NioTotipo, with injected
provider fixtures only for inaccessible failure/hostile-storage conditions. They
cover session lifecycle and immutability; real Flow demand, replay, coalescing,
independent subscribers, invalid demand and terminal ordering; exact update and
merge bases; receiving-state versus later-session selection; cross-session/token
rejection; secret groups/merge choices; historical/tombstone/local TOTP; causal
additional conflict including equal-valued heads, ancestry resolution and
cross-token ancestry isolation; unavailable merge checks; independent handles;
monotonic uncertainty and exact single/fold retries; concurrent close before and
after mutation entry and during an already-uncertain retry; secret ingress; and
open/create/password authentication, staging, stale and uncertainty taxonomies.
Two NIO adapter tests separately verify exact-existing acknowledgement barriers
and refusal to acknowledge when a barrier fails.

All original 312 tests remain, plus these 52 tests: 364 total, zero failures,
errors or skips. All 90 r17 cases pass unchanged. Full verification also builds
both modules and checks every production class's Java-17 target. No original
lower-level suite or corpus test was removed/replaced.

Evidence is from the current case-sensitive Linux filesystem with the existing
suite's hard-link, symlink, atomic-move, directory-channel force, POSIX and mkfifo
assumptions. Fault fixtures model acknowledgements and concurrency, not physical
power loss. Windows/macOS/Android qualification, independent interoperability,
remote sync completion and rollback resistance are not claimed.

## API deviations and concrete choices

* Java interfaces/records and enum variants implement the conceptual shapes;
  password outcomes use uppercase enum constants. There is no public state ID.
* Progress emits initial Enumerating and completed Finished states; Processing
  remains a permitted type, not a fabricated percentage or freshness indicator.
* ClientMetadata exposes optional raw unsigned-u64 time bits, preserving the full
  protocol domain without interpreting them as an Instant.
* `TokenEditor<T>` shares fluent fields while keeping three distinct builders.
  Merge unresolved field names are strings; internal agreement state is private.
* `NewSecret.copy()` exports only caller-owned ingress, never existing vault
  secrets, and documents caller wiping responsibility.
* Retry calls consume their current handle and transfer capability to a fresh
  uncertain result; this makes successor ownership unambiguous. Partial save
  transfers similarly. AdditionalConflict makes the original merge terminal.
* Definite provider pre-write failures after entry to the existing coarse
  publication boundary are conservatively uncertain. No SPI redesign is needed
  to preserve monotonic knowledge. Initial creation races after installation
  entry are likewise conservatively Uncertain, not asserted AlreadyExists.
* The NIO entry point requires an existing configured-store directory and accepts
  relative paths by resolving them to absolute paths internally.

These choices do not weaken causal selection, secret ownership, publication
certainty, stream ordering or the pinned protocol semantics.

## Open issues

No unresolved acceptance blocker is known. Intentional limits remain: retained
historical secrets grow until session close; the accepted merge/rewrap check races
are not CAS; durability depends on the configured provider capability; the
provider/internal SPI is not stabilized. These limits and the deferred deployment,
platform qualification and sync work are documented rather than claimed solved.

## Narrow remediation pass: four review findings

The pass began from the uncommitted facade above at the same HEAD, with 346 passing
tests (288 core, 58 storage-nio), 32 facade tests and 3,436 production Java LOC.
After that four-finding pass (before the lifecycle pass below): 355 tests
(297 core, 58 storage-nio), 41 facade tests and 3,497
production Java LOC, a net increase of 61 production lines. The two NIO adapter
tests remain unchanged. All 90 r17 cases still execute unchanged, without skips.
No protocol, storage format, SPI, dependency or Java target changed. No commit
was made. The full final verification command is `./gradlew test build`.

### 1. Local operations independent of provider I/O

The existing provider gate still serializes observation, publication, exact retry,
password change and resource cleanup. A separate local lock protects canonical
secret/value maps, ingress overrides, builder registration, TOTP, local operation
freezing, post-read projection/interning and the lifecycle transition. Provider
I/O, KDF and graph evaluation do not hold that local lock. Fluent setters,
factories and TOTP never acquire the provider gate.

The only nested acquisition order is provider then local. Close marks closing
under local, releases it, then acquires the provider gate; it never waits for
provider I/O while holding local. Root use during provider work is protected by
the gate. TOTP holds local while using its resolved secret. Final wiping holds
both locks after in-flight provider work finishes, preserving Saved/Uncertain
knowledge. Registered builders and frozen ciphertext operations remain owned by
the session. Public states still contain no secret bytes.

New tests `localOperationsCompleteWhileObservationIsBlocked` and
`localOperationsCompleteWhilePublicationIsBlocked` hold provider latches closed
while TOTP, setter/secret-ingress changes and a new builder complete on another
thread. They verify completion before releasing I/O, not merely eventual success.
Existing close-before-publication, close-during-publication and close-during-
uncertain-retry tests continue to pass. Builders remain thread-confined: the tests
edit a different builder from the blocked publication's builder.

### 2. Stable descriptive capability identity

`TokenHead.equals/hashCode` use owning session identity, logical TokenId and exact
revision. `TokenAlternative.equals/hashCode` use owning session identity, TokenId
and the canonical session value key. That key represents complete semantic value
equality, including the secret internally. Heads, metadata, observation sequence
and visible descriptor alone do not define alternative identity. Equality and
hashing need no live secret lookup and remain stable after close.

`projectionEqualitySurvivesStatesChangedHeadSetsAndClose` checks equal heads across
states, equal alternatives with different captured head sets, hash consistency,
HashMap/HashSet UI selection use and post-close stability.
`alternativeIdentityIncludesSecretTokenAndSession` checks identical descriptors
with different secrets, different token IDs and equivalent data from a different
session; foreign capabilities remain unequal and rejected for mutation.

### 3. Deliberately narrower result types

The preferred narrower type decision was implemented. `PartialResolution.save()`
returns sealed `PartialSaveResult`, admitting Saved, Failed and PublicationUncertain
only. `PublicationRetry.retryPublication()` returns sealed `RetryResult`, admitting
Saved and PublicationUncertain only. RetryResult extends PartialSaveResult, which
extends SaveResult; the existing nested result records are shared across all
three interfaces, so applications can still use common SaveResult handling.
There are no duplicate payload records, conversions, or casts from a general save
result. The internal exact-retry path itself returns RetryResult, structurally
excluding Failed and AdditionalConflict. Builder save still returns SaveResult.

`handleResultTypesExcludeImpossibleVariants` checks the public method return types
and complete sealed subtype inventory. Existing ambiguous-then-prewrite-failure,
exact fold retry, partial save, handle transfer and close-race tests exercise the
runtime paths. Monotonic uncertainty and exact frozen identity are unchanged.

### 4. Deterministic termination and reentrant close

Both refresh and merge-prepublication observation route fatal machinery exceptions
through one session termination path. The first transition to closing records
an immutable cause: explicit close selects completion; fatal termination selects
onError with that exact cause. A later competing termination cannot overwrite it.
Provider cleanup finishes before terminal delivery is requested. The publisher
also guards terminal selection and ignores post-terminal demand. A subscriber
with an earlier invalid-demand error retains that subscriber-specific error;
cancelled subscribers have abandoned delivery.

Callbacks run outside the provider gate, local lock and publisher monitor.
Reentrant `close()` never waits for subscriber callbacks or common-pool drain
completion. It returns after session cleanup, and the currently executing drain
delivers its single terminal signal after onNext returns. No onNext follows it.

New tests are `closeFromOnNextCompletesWithoutWaitingForItsOwnCallback`,
`fatalObservationErrorsCurrentAndLateSubscribersExactlyOnce`,
`fatalMergeObservationAlsoTerminatesTheSessionWithItsCause`, and
`explicitCloseWinningFatalRaceKeepsCompletionForAllSubscribers`. They verify
resource closure, callback order, original error identity, current/late subscriber
consistency and preservation of the first terminal outcome in both race orders.

### Remaining limits after remediation

Local operations no longer wait behind unrelated provider I/O, but this is not
a real-time latency guarantee. Local CPU work, projection/interning size, crypto
and scheduling can still contend for the local lock. Close can wait indefinitely
for a provider that never returns, as required to avoid fabricating certainty;
reentrant close has the same provider-wait limitation but no callback self-wait.
Fatal JVM/process failure that prevents Java code or callbacks from executing
cannot guarantee signal delivery. Existing history-retention, provider durability,
non-CAS race and platform/sync qualification limits remain unchanged.

## Narrow lifecycle remediation: exact VAULT reads and read-only NIO open

This pass began from 355 passing tests and 3,497 production Java LOC at the same
uncommitted HEAD. It adds nine application-facing tests: final counts are **364
tests (306 core, 58 storage-nio), including 50 facade tests**, with zero failures,
errors or skips. Production Java LOC is **3,508**, a net increase of 11 lines.
The full `./gradlew test build` passes; all 90 r17 corpus cases remain unchanged.

### Exact record length and password-change classification

The review request called the valid record 88 bytes. The actual pinned r17
specification (`core/src/test/resources/totipo-spec/v1-pre-rc/spec/totipo-vault-format-v1.md`,
bootstrap layout) and existing `VaultBootstrap.RECORD_BYTES` constant specify
**87 bytes**. The 88-byte read limit is one-byte lookahead, not a valid record
length. Previous BASE authentication and staged byte equality already rejected
long inputs downstream; there was no valid 88-byte prefix accepted by r17.

`ApplicationVaults.read()` now explicitly requires exactly the shared
`VaultBootstrap.RECORD_BYTES` length. It requests at most that length plus one,
wipes rejected bytes and throws IOException on short or long records. It does
not readAllBytes or drain trailing content. Null streams still represent absence.
This same helper covers authenticated BASE, immediate CURRENT, staged initial
creation and staged replacement. Invalid staged records cannot reach either
installation method. No low-level codec, protocol constant or storage format was
changed.

The immediate comparison now checks null separately: missing CURRENT yields
FAILED instead of Arrays.equals(base, null) yielding STALE. Unreadable or
wrong-length CURRENT is also FAILED as an unusable required observation. A
present exact-length record whose bytes differ from BASE remains STALE; equality
allows the existing replacement path. The residual compare-to-replace race and
post-attempt uncertainty classification are unchanged.

Seven new lifecycle tests use MemoryVault fault seams and attempt counters:

* `passwordChangeRejectsTrailingOrShortBaseWithBoundedRead`: rejects short,
  one-byte-overlong and much longer canonical BASE; checks the read bound and
  absence of replacement attempts.
* `passwordChangeRejectsCanonicalTrailingDataAddedBeforeComparison`: appends data
  after staging; CURRENT cannot be treated as unchanged and replacement is not
  attempted.
* `stagedReplacementWithTrailingDataIsRejectedBeforeReplacement`: exact candidate
  plus one or many trailing bytes is rejected, preserving canonical bytes.
* `stagedInitialBootstrapWithTrailingDataIsRejectedBeforeInstallation`: exact
  candidate plus trailing data never enters initial installation.
* `canonicalDisappearanceBeforeReplacementIsFailedNotStale`: removal after staging
  produces FAILED without replacement.
* `unusableCurrentObservationFailsWhileExactChangedBytesAreStale`: unavailable or
  truncated CURRENT fails; a different exact-length CURRENT is still STALE.
* `exactProtocolLengthCreationAndPasswordReplacementRemainSuccessful`: exact
  87-byte creation and replacement succeed, retain the fingerprint, and reopen
  with the new password while authentication with the old password fails.

The fixture's instrumented InputStream bounds consumed bytes per read stream to
the valid-record length plus one, including much longer trailing inputs. No
production validation is relaxed for the tests.

### NIO-open inspection and black-box evidence

Inspection of the unchanged construction chain confirms:
`NioTotipo.open` constructs `NioApplicationPublication`, whose constructor calls
`NioV1ObjectPublicationStore.open`. That method only validates the existing root
through `NioFiles.root`/`directory` and stores provider references. It does not
create `objects-v1`, stage files, publish or force directories. Namespace creation
is inside `publish`. Bootstrap open likewise validates/reads only; discovery
treats an absent object namespace as an empty local observation. No construction
refactor or production NIO change was necessary.

`nioOpenIsReadOnlyWithNoObjectNamespace` exercises Opened, AuthenticationFailed,
InvalidVault, Absent and Unavailable outcomes while objects-v1 remains absent.
`nioOpenDoesNotRepairExistingProtocolFiles` exercises successful and unsuccessful
opening with a malformed canonical object file already present. These tests
snapshot the whole fixture tree before/after opening (and after initial
observation/session closure on success), comparing directory entries, file bytes,
file identity keys and modification times. No creation, replacement, repair or
other protocol-content/namespace mutation is observed. Read-induced access-time
updates are intentionally outside this read-only-content assertion.

### Preserved scope

Only the facade lifecycle reader/comparison changed in production. The provider/
local lock split, local TOTP independence, stable equality, deterministic causal
bases, M/F0/F1 checks, narrowed result types, monotonic uncertainty, exact retries,
handle ownership and stream/reentrant-close behavior are unchanged and retain
their tests. Dependencies, Java target, NIO provider boundaries and all original
r17 suites remain unchanged. Existing provider/platform qualifications and
compare-before-replace limitations still apply. Changes remain uncommitted.
