# Totipo v1/r18 CausalFact metadata audit

## Summary

**Classification A / Outcome A: derived causal index. No production semantic fix
is required.** `CausalFact` retains causal/topological facts derived from a validated
TOKEN but does not retain or represent that TOKEN object itself. §12 therefore does
not require CLIENT metadata in this index. Actual current/captured TOKEN heads and
retained complete TOKEN models preserve exact metadata independently.

The previous historical-metadata qualification is removed. Audited facade TOKEN
projections and metadata handling in create/update/merge, partial resolution and
frozen publication retries are included in the corresponding operation-scoped core
claims. This is not blanket certification of every facade operation. Application
conformance is not claimed; application-observation limitations remain.

## Committed baseline

- HEAD: `bc256830d6f44dff214d33ef3017115c993b382f` (`r18 repin`).
- Implementation version: `0.1.0`, from `VERSION`; unchanged by this audit.
- Spec: Totipo v1/r18 at `4623a7e1718e23504903096c92332597057bd8f0`.
- Initial `git status --short`: empty, confirming a clean committed baseline before
  any source/documentation edits. No applicable `AGENTS.md` was found.
- Initial claims: core protocol foundation (bootstrap, crypto/identity,
  TOKEN encoding/validation/metadata, graph/current state, complete-value equality,
  folds, TOTP); qualified low-level NIO/core store operations; no application claim.
  README/API_DESIGN and the repin report withheld a blanket facade core claim because
  the retained `CausalFact` index had not been classified under §12.
- `SPEC_PIN.md`, all vendored spec/profile/corpus files, `VERSION`, dependency locks,
  dependency-verification metadata and build configuration are unchanged.

## §12 interpretation

Authority: the [vendored pinned r18 spec](../core/src/test/resources/totipo-spec/v1-pre-rc/spec/totipo-vault-format-v1.md),
§12, especially lines 440–463; §§15–17 provide the related head/value/fold rules.

For as long as a validated TOKEN object is represented, returned, exposed or
retained, its CLIENT_NAME and CLIENT_TIME must be preserved exactly **with that
object**. Exactness includes absent versus present-empty name, the exact validated
UTF-8 value/bytes, absent versus zero time, and every unsigned u64 value. An object
representation cannot normalize, synthesize, replace, merge, select or drop metadata.

The adjacent clarification does not require indefinite retention of previously
observed objects, metadata or graph facts after the store stops supplying them.
It creates no advisory-history, remembered-head, cache or cross-run persistence
requirement. Disposable indexes can outlive the bytes from which they were derived;
the preservation rule still applies to any actual TOKEN representation retained.
§2 also expressly permits caches of validated bytes or derived indexes while
forbidding their use as a second normative object source or silent replacement for
missing store ancestry. Here graph evaluation uses only the current validated
observation; captured links are private knowledge for a merge's containment check,
and do not resolve missing edges or supply historical nodes to TokenGraph.

An OBJECT_ID commits to an object's contents but a private identity/ancestry index
is not thereby a representation of its value or metadata. Classification here rests
on all consumers, rather than the record's name or the mere absence of fields.

## Usage trace

Source: [ApplicationSession.java](../core/src/main/java/org/totipo/format/ApplicationSession.java).

| Location / path | Complete behavior relevant to CausalFact |
| --- | --- |
| Definition, line 42 | Private nested record with exactly `org.totipo.TokenId token` and `List<ObjectId> parents`. `token` is logical identity, not TokenValue. OBJECT_ID is the surrounding map key, not a record field. There is no value key, descriptor, metadata, TOKEN model, plaintext or ciphertext. |
| Constructor / factories | Only the implicit record canonical constructor; no factories or custom copy constructor. The sole creation site is `observePass`, line 116. Parents come from the immutable, validated `TokenObject.parents()` list. Generated identity/record methods have no semantic presentation consumer. |
| Validation and creation | `TokenStoreReader.read` authenticates exact OBJECT_ID/envelope and parses canonical TOKENs. `TokenGraph.evaluate` excludes contradictory identities and partitions by TOKEN_ID. `observePass` creates one link for every surviving `view.objects()` entry, including non-heads, in a new local `links` HashMap. |
| Current session storage | `ancestry` starts empty; `observePass` replaces it with `Map.copyOf(links)` at line 132 on every pass. It does not cumulatively accumulate historical links. An empty/unavailable observation may replace it with an empty index. |
| State snapshot storage | `State.causalFacts` privately retains `Map.copyOf(causalFacts)` at line 264; the initial state uses an empty map. `current`, `ApplicationStates.latest`, subscriber delivery and caller-held old states can retain these snapshots. Public State methods expose tokens/diagnostics/progress, not causal facts. |
| Merge capture | Both `State.merge(TokenId)` and `State.merge(Collection)` converge on line 299, passing the receiving state's index into `Merge.originalAncestry` (lines 419–423). Selected basis M and complete frontier F0 come from actual captured heads. Competition and secret choices come from selected alternatives and interned complete values, never the index. |
| Sole data consumer | `Merge.additional`, lines 441–459, walks OBJECT_IDs from F0. It reads `originalAncestry.get(id)` and current `ancestry.get(id)`, checks each fact's token identity, then queues parents. It returns whether any currently observed head lies outside the resulting containment set. Both captured and newly resolved links can contribute. No other method reads fact fields or iterates these maps for presentation. |
| Save path | `Editor.save` freezes a plan from selected M/value/operation metadata, then reobserves and calls `Merge.additional`. The facts affect only the additional-information decision. They do not construct parents, values, descriptors, heads, metadata or fold stages. AdditionalConflict exposes the freshly observed State, not historical facts. |
| Ordinary update | Both update overloads derive basis IDs from supplied/captured/current equal heads and prefill complete values via the head/alternative value key. They do not access causal facts. Historical updates require a real retained head or alternative. |
| Publication / retries | `Frozen`, `Partial` and `Retry` keep/use exact already-authored envelopes; they do not access ancestry or reconstruct historical TOKENs. Saved revisions are identity receipts. |
| Lifetime and closure | Old State/merge maps can survive observation passes and disappearance/collection of source bytes and parsed models. Termination clears session `ancestry`, root and value/secret registry, but caller-held descriptive states, heads, alternatives or closed merge objects can still keep their immutable fields/maps until unreachable. Metadata in actual captured heads remains readable after close. There is no cross-session/cross-run persistence of causal facts. |

All direct references and surrounding save/update/merge/conflict/publisher paths
were inspected. The map keys and values have no API accessor or historical lookup.
No caller can recover a dropped historical TOKEN's value, CLIENT metadata or head
using this index alone. Reference IDs and unresolved edges are causal facts, not
complete or partially reconstructed historical TOKEN models.

The session also retains `values: Map<Long, TokenValue>` and
`valueIds: Map<TokenValue, Long>` until close. These intern complete **semantic
values**, excluding TOKEN_ID/parents/CLIENT metadata by protocol definition.
They do not associate historical OBJECT_IDs with values. A captured Head's key and
metadata plus its Alternative provide the historical capability; CausalFact cannot
substitute for a missing Head. No future Head can be built from these links.

## Public metadata audit

| Representation / projection checked | Metadata result |
| --- | --- |
| `TokenObject`, `ValidatedToken`, `TokenStoreObservation.validatedTokens` | Complete retained TOKEN models carry immutable TokenMetadata. Parsing preserves Optional presence and exact strict UTF-8 strings/u64 bits; writer re-encodes exact canonical values. |
| `TokenGraph.View.objects`, heads and SCC/currentGroups | Lists retain original ValidatedToken objects with their own metadata. Equal semantic values/SCC grouping does not select a representative object's metadata. Graph currentValues is only a semantic-value projection. |
| `TokenHead` / `ApplicationSession.Head` | Every construction copies metadata from that exact validated head via `metadata(TokenMetadata)`. Final ClientMetadata field; no setter/defaulting. Equality excludes metadata because session/token/revision is object identity, without removing the stored metadata. |
| `TokenAlternative` / Alternative | Semantic identity and descriptor project complete TokenValue. Immutable heads list retains every distinct equal-valued object and its own metadata; equality ignores captured heads without coalescing/deleting those lists. |
| `TokenState` / Token | Immutable heads and alternatives preserve each head. hasConflict tests distinct complete values, not CLIENT fields. Equal values may be unconflicted while retaining multiple object identities and exact metadata. |
| `VaultState` / State, current/previous/captured/read-only views | Immutable lists retain actual Heads/Alternatives, including after later observations, disappearance and close. Private causalFacts do not supply public tokens. There is no separate historical-object enumeration DTO. |
| `TokenCompetition`, CompetingField.Value, CompetingSecret/SecretGroup, `MergeSecretChoice` | These group fields/secrets from alternatives while retaining original alternative/head references with metadata. They make no claim to represent an object via a chosen descriptor. |
| Merge inputs and AdditionalConflict.latest | Inputs retain selected alternatives and heads; latest is a newly observed State whose heads carry their own metadata. No latest-metadata winner is chosen. |
| Editor / TokenPublicationPlan / TokenFold.Stage | A builder authors new objects, rather than reconstructing its parents. Its metadata defaults to absent and can be set explicitly. Every operation stage uses that exact operation metadata independently of parent metadata. |
| Frozen/Authored, PartialResolution, PublicationRetry | Each retained envelope contains exact encoded operation metadata. Partial save/retry uses the same frozen bytes; no time refresh, name substitution or rebuilding from causal facts. |
| TokenDescriptor, interned TokenValue, TOTP output | Semantic/credential projections, not representations of any particular TOKEN. They do not take metadata from CausalFact or become historical object models. |
| RevisionId, UnresolvedReference, SaveResult.Saved | Identity/edge/publication receipts, not TOKEN content DTOs. No value or metadata reconstruction. |

`TokenReader` and `StrictUtf8` neither trim nor normalize. Valid canonical UTF-8
round-trips through Java strings exactly. `TokenMetadata` -> `ClientMetadata`
conversion maps `UInt64.rawBits`; the reverse wraps exactly those long bits.
Neither conversion filters empty strings/zero nor performs signed-time validation.

The new public API parameterized test covers the Cartesian product of three names
(absent, present-empty, exact nonempty with whitespace/NUL/newline/decomposed
combining text/supplementary Unicode) and five times (absent, zero, positive one,
high-bit `Long.MIN_VALUE`, unsigned maximum/raw `-1L`). Existing codec tests verify
exact byte round trips; graph and fold/publication tests verify per-object/stage
preservation. All seven required presence/string/unsigned conditions are covered.

## Merge/update assessment and decision

Outcome A satisfies all classification criteria: only causal identity/topology is
stored; it is private; no completeness or object-retention claim is made; no caller
can substitute it for a TOKEN; no semantic presentation comes from it; merge uses
it only for containment; actual retained representations keep metadata separately.

Captured links let a later merge recognize ancestry even when intermediate source
objects disappear. This is retained knowledge of relationships, not retained object
state. It does **not** automatically expand the authored parent basis. The authoring
basis remains the selected actual heads, including explicit unavailable parent IDs.
A disappearing intermediate is not fabricated into a current/historical head.

No path substitutes empty metadata for an existing head, synthesizes it, copies it
from another head, uses latest CLIENT_TIME or collapses equal-value object metadata.
A new update/merge object's independently chosen absent metadata is permitted and
is not replacement of its parents' metadata. New tests explicitly check this.

Adding metadata to CausalFact would be cosmetic and would blur this distinction.
There is no persistent historical-object database or new retention requirement.

## Implementation changes and source-diff audit

**Production semantic code change: none.** No field, method signature or method
body changes. Four production files contain only comments/Javadocs:

- ApplicationSession: document the causal index, observation replacement, interned
  semantic values versus TOKENs, and containment-only consumer.
- TokenHead: exact revision metadata remains readable on captured heads.
- TokenAlternative: distinguish semantic descriptor from per-head metadata.
- TokenDescriptor: explicitly document a semantic projection, not a specific TOKEN.

All 106 tracked production Java files have identical non-comment source tokens to
HEAD. Fresh baseline compilation captured all 202 production classes before edits;
post-validation disassembly comparison is recorded below. Source-token equality and
bytecode comparison distinguish documentation/debug-line changes from semantics.
The complete production diff was inspected; no unrelated logic changed.

## Conformance impact

- **Core:** existing protocol-foundation operations retain their claim. Audited
  facade TOKEN projections and metadata handling for create/update/merge, including
  AdditionalConflict, partial resolution, folds and frozen retries, are included
  within those corresponding operations. This focused audit does not certify every
  facade operation, scheduling/lifecycle behavior or application policy.
- **Store:** existing qualified local case-sensitive Linux NIO/core observation,
  immutable publication, initial installation, exact compare-before-replace,
  replacement, byte preservation and explicit durability claims are unchanged.
- **Application:** not claimed. Existing limitations remain: NioTotipo.create
  supplies no pre-creation orphan context/result; facade diagnostics lack arbitrary
  unavailable-candidate attribution; observation cannot establish universal
  freshness/rollback resistance; consuming applications implement warnings,
  confirmations, alternative disclosure and safe untrusted-text presentation.
- **Previous facade historical-metadata qualification:** resolved and removed.
  Operation-scoped claims and provider/application limitations remain explicit.

## Tests

Changes are confined to `PublicApiTest`; no implementation-private assertions:

1. `representedMetadataSurvivesRefreshDisappearanceReappearanceAndClose`:
   15 parameterized invocations checking exact metadata on direct/alternative heads,
   refreshed and captured states, source removal/reappearance and close. A new update
   with absent operation metadata leaves the captured parent's metadata intact.
2. `capturedMergeAncestrySurvivesMissingIntermediateWithoutRepresentingIt`:
   captured C -> B -> A ancestry accepts reobserved A after B/C disappear, without an
   AdditionalConflict or fabricated B/C heads. Actual selected/captured heads keep
   their metadata, and the authored resolution has its exact independent metadata.
   Available-only graph semantics still leave A current alongside the resolution.
3. `equalHeadsAndConflictResolutionKeepPerObjectMetadataThroughPartialRetryAndFold`:
   six equal-valued heads plus a conflicting head retain per-revision metadata;
   merge choices and a late equal-valued head preserve it; AdditionalConflict/partial
   resolution and uncertain retry retain the original operation across a two-stage
   fold. Result metadata and captured input metadata remain exact.

17 new invocations; baseline 461 tests becomes 478. Existing codec, graph, fold and
publication tests supplement the public assertions. Outcome A needs no formerly
failing metadata-retention fix test; these tests lock in the conformance boundary.

## Validation

| Command / evidence | Result |
| --- | --- |
| `./gradlew :core:compileJava :storage-nio:compileJava`, then `./gradlew --rerun-tasks :core:compileJava :storage-nio:compileJava` before production edits | PASS; captured freshly compiled baseline production class hashes/disassembly. |
| `./gradlew :core:test --tests org.totipo.api.PublicApiTest --tests org.totipo.format.TokenCodecTest --tests org.totipo.format.TokenGraphTest --tests org.totipo.format.TokenFoldTest --tests org.totipo.format.TokenPublicationTest` | PASS: 126 tests; zero failures/errors/skips. |
| `./gradlew clean test build verifyPublication consumerSmoke` | PASS: 478 tests (core 363, storage-nio 115); zero failures/errors/skips; 90/90 portable cases. |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test build verifyPublication consumerSmoke` | PASS: all 30 outer tasks executed; same 478 tests and 90/90 cases, zero failures/errors/skips. |
| `./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check` | PASS: standalone POM-only consumer compile/check and dependency boundary. |
| Snapshot/profile integrity, both full runs | PASS: SpecSnapshotIntegrityTest 3/3, R18ProfileIntegrityTest 1/1; exact pin, all snapshot/profile hashes and inventory intact. |
| Java 17 production bytecode checks, both full runs | PASS for core and storage-nio; all class major versions 61, no preview bytecode. |
| `verifyPublication`, both full runs | PASS: exact POM/module dependency scopes, binary/source/Javadoc contents, Java 17 classes, unsigned artifact/checksum inventory. No external publication performed; staging is local build output. |
| `consumerSmoke`, both full runs | PASS: standalone module-metadata consumer and compile/runtime boundaries; BC stays runtime-only. Consumer has no test sources, as designed; no skipped test invocations. |
| Dependency verification | PASS: strict mode enabled in committed gradle.properties; normal, forced offline and both consumer modes succeed without verification/lock exceptions or changes. |
| Production source tokens | PASS: all 106 production Java files match HEAD with comments/whitespace excluded. |
| Production bytecode comparison | PASS: all 202 classes have byte-identical `javap -c -p -s` output against freshly compiled baseline, including signatures/fields/instructions. 186 raw class hashes are identical; 16 differ with source-line shifts in TokenDescriptor and ApplicationSession/nested classes. No instruction/signature change. |
| `git diff --check` | PASS. |
| Nix validation | NOT RUN: `command -v nix` finds no executable. README documents `nix develop` as a build environment; the flake provides a dev shell, not an independent checks target. The Java validations above used available JDK 25.0.4.1 and pinned Gradle 9.8.0. |

Other-platform/provider qualification, physical power-loss testing and external
interoperability/release/signing are not part of this focused audit. Build logs and
baseline/final comparisons are in `/tmp/totipo-causal-*.log` and related temporary
evidence files; the commands/results and stable counts are recorded here.

## Portable compatibility

The full corpus executor asserts 90 executed unique cases with no deferred category
and checks the unchanged category counts: bootstrap 4, crypto 5, encoding 30,
fold 6, graph 13, metadata 7, size 1, storage 13, TOTP 3, VAULT 8. **90/90 pass**.
Snapshot/profile integrity checks confirm the unchanged exact r18 pin/hashes/cases.

No TOKEN bytes or CLIENT encoding, OBJECT_ID/crypto, reachability/SCC/head selection,
TokenValue equality, fold construction, publication/store behavior, password behavior,
TOTP or corpus case/outcome changed. No portable case changed or required investigation.

## Files changed

| File | Reason |
| --- | --- |
| `README.md` | Remove historical-metadata qualification; include audited facade metadata/projection operations with bounded core scope. |
| `API_DESIGN.md` | Explain derived index, independent heads, authoring metadata and final scoped claims; retain application limitations. |
| `SPI_DESIGN.md` | Confirm derived indexes impose no historical persistence/store change. |
| `RELEASE_CHECKLIST.md` | Replace unresolved metadata review gate with audit evidence; retain release/provider/application gates. |
| `core/src/main/java/org/totipo/format/ApplicationSession.java` | Comments/Javadoc only defining the causal-index/semantic-value distinction. |
| `core/src/main/java/org/totipo/TokenHead.java` | Javadoc for exact captured revision metadata. |
| `core/src/main/java/org/totipo/TokenAlternative.java` | Javadoc for value projection and independent equal-head metadata. |
| `core/src/main/java/org/totipo/TokenDescriptor.java` | Javadoc for semantic projection. |
| `core/src/test/java/org/totipo/api/PublicApiTest.java` | Three focused tests / 17 invocations exercising public conformance boundaries. |
| `review/V1_R18_REPIN_REPORT.md` | Mark the earlier metadata question resolved by this subsequent audit; retain historical repin validation/diff evidence. |
| `review/V1_R18_CAUSAL_FACT_METADATA_REPORT.md` | This complete focused audit and validation record. |

## git diff --stat

```text
 API_DESIGN.md                                      |  26 +++--
 README.md                                          |  12 ++-
 RELEASE_CHECKLIST.md                               |  10 +-
 SPI_DESIGN.md                                      |   5 +
 .../src/main/java/org/totipo/TokenAlternative.java |   2 +
 core/src/main/java/org/totipo/TokenDescriptor.java |   1 +
 core/src/main/java/org/totipo/TokenHead.java       |   1 +
 .../java/org/totipo/format/ApplicationSession.java |  13 ++-
 .../test/java/org/totipo/api/PublicApiTest.java    | 110 +++++++++++++++++++++
 review/V1_R18_REPIN_REPORT.md                      |  42 ++++----
 10 files changed, 188 insertions(+), 34 deletions(-)
```

The literal `git diff --stat` excludes this new untracked report; all changed files
including the report are listed above and in status below.

## git status --short

```text
 M API_DESIGN.md
 M README.md
 M RELEASE_CHECKLIST.md
 M SPI_DESIGN.md
 M core/src/main/java/org/totipo/TokenAlternative.java
 M core/src/main/java/org/totipo/TokenDescriptor.java
 M core/src/main/java/org/totipo/TokenHead.java
 M core/src/main/java/org/totipo/format/ApplicationSession.java
 M core/src/test/java/org/totipo/api/PublicApiTest.java
 M review/V1_R18_REPIN_REPORT.md
?? review/V1_R18_CAUSAL_FACT_METADATA_REPORT.md
```

## Release assessment

The metadata question is sufficiently resolved for the intended **v0.1.1
r18-alignment release**, within the documented operation-scoped claims and existing
provider/application limitations. No metadata implementation fix or facade redesign
is needed. Version remains 0.1.0; this audit does not perform version selection,
release approval, signing or publication. Nix/platform/power-loss evidence is not
expanded here. All changes remain uncommitted for review. No commit, tag, release
or push was performed.
