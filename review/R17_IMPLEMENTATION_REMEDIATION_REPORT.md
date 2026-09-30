# Totipo Java r17 — targeted remediation report

This milestone remediates the committed Phase 5 implementation using
`R17_IMPLEMENTATION_ADVERSARIAL_REVIEW.md`, findings F1–F6. It does not redesign
r17 or begin public Java API design. All changes remain uncommitted.

## Baseline and pin

Starting HEAD: `86eecbd73fbffee161bf74e56b065998bdef2cea` (committed Phase 5).
The first commands were `git status --short` and `git rev-parse HEAD`.
Complete starting status:

```text
?? R17_IMPLEMENTATION_ADVERSARIAL_REVIEW.md
```

The review was preserved byte-for-byte, SHA-256
`660add8dabceb898ccb3b2a251968aae6ec7c74490a6ab13f5ba86358e90bb8f`.
All six findings were re-read and confirmed against current source before edits.
No unrelated baseline failure was repaired.

Before editing, `./gradlew clean test build` and the isolated
`./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test`
both passed: **297 tests (252 core + 45 storage-nio), zero failures, errors,
or skips; 90/90 portable cases executed**. Both runtime dependency reports,
both Java 17 bytecode tasks, focused snapshot/profile integrity tests, and all
97 `SNAPSHOT.sha256` records passed. Javadoc emitted existing missing-comment
and parameter warnings. A supplementary LOC-count attempt found Python unavailable;
standard shell tools supplied the count instead. No validation depended on Python.

The exact upstream r17 pin remains
`1d42a481f230e0adbb89dbeaa936d3c956e70fdc`.
No snapshot, corpus, hash, location, normative provenance, or upstream specification
was changed. `SPEC_PIN.md` changed only implementation-status/accounting prose.

## Finding disposition

| Finding | Before | After | Disposition |
| --- | --- | --- | --- |
| F1 | BLOCKER | resolved | Exact canonical spelling enforced |
| F2 | MEDIUM | resolved | No attacker-hash duplicate check |
| F3 | MEDIUM | open | Intentionally deferred to public API design |
| F4 | LOW | resolved | Constant redacted string |
| F5 | LOW | resolved | Current documentation corrected |
| F6 | LOW | mitigated/open | Environment/provider scope documented; target qualification later |

## F1 — exact observed canonical entries

The original defect was a mismatch between lookup and enumeration: requesting a
lowercase path could resolve an uppercase entry on an aliasing provider, while
ordinary discovery rejected the uppercase filename. Publication could therefore
return `ALREADY_PRESENT_EXACT` for an object discovery omitted. Direct `vault`
lookup could similarly open `VAULT`; `OBJECTS-V1` could become the namespace.

`NioFiles.findExactDirectChild` now enumerates only the parent, compares the actual
`entry.getFileName().toString()` using exact `String.equals`, and returns the actual
enumerated Path. It neither recurses nor follows/inspects the candidate. The
stream is closed with try-with-resources. I/O errors propagate, including iterator
I/O failures unwrapped from `DirectoryIteratorException`; unsuccessful enumeration
cannot establish absence. Its package-private selection function permits host-
independent tests without a new filesystem library or production abstraction.

Boundaries and operation-local paths:

- `NioDiscoverySource` establishes exact `objects-v1` spelling from root enumeration
  before the existing no-follow directory check and direct object enumeration.
- `NioV1ObjectPublicationStore` uses the exact observed namespace if present.
  Otherwise it attempts normal creation and re-enumerates. A creation collision
  is accepted only if an exact concurrent winner is observed; an uppercase-only
  collision fails without entering or modifying that sibling. Namespace creation
  remains lazy. Existing root-barrier retry behavior is retained.
- Both publication comparison paths (initial observation and hard-link collision)
  require an exact observed object filename. Only that returned Path is read.
  A collision with no exact entry propagates failure, never exact-existing success.
- `NioVaultBootstrapStorage.openCanonicalRead` returns canonical absence only after
  successful enumeration finds no exact `vault`; uppercase `VAULT` is ignored.
  Replacement requires an exact observed `vault`, checks its regular-file type,
  and moves to that observed Path. Initial installation still uses a no-replace
  hard link to lowercase `vault`; alias collision is an error, never an overwrite.

Exact-existing publication remains a bounded 1,025-byte comparison, without
crypto, rewrite, chmod, timestamp mutation, or a fresh object durability barrier
for reconfirmation. Already established exact Paths are reused within the
operation; extra enumeration is limited to initial observations and creation or
collision re-observation. No persistent namespace cache was added.

BASE authentication, CURRENT byte comparison, STALE semantics, one replacement
attempt, and the accepted compare-before-replace race are unchanged. No native
code, inode pinning, global lock, provider blacklist, or expanded same-UID racing
threat model was introduced. Existing no-follow/type checks remain in place.

### Regression evidence and original reproducer reasoning

`NioExactNameTest` covers:

- Pure actual-name selection for `vault`, `objects-v1`, and a lowercase 64-hex ID:
  uppercase/mixed names fail exact selection; exact names return the same Path.
- Direct-only enumeration, an unfollowed dangling symlink, and failure rather than
  absence when parent enumeration cannot open the directory.
- Uppercase-only VAULT canonical absence, replacement refusal, normal lowercase
  sibling creation on this case-sensitive host, and unchanged uppercase bytes/time.
- Uppercase namespace exclusion from discovery, lazy canonical sibling creation,
  and unchanged noncanonical contents.
- Injected namespace creation collisions with an exact concurrent winner versus
  only an uppercase alias, using one method in the existing internal Operations seam.
- Injected object link collisions with exact versus uppercase-only winners; aliases
  never reach byte comparison, exact success agrees with ordinary discovery, and
  temporary files are cleaned up.
- Initial VAULT alias collision failure without modification or acknowledgement.

`TokenNioWorkflowTest` adds uppercase and mixed-case valid encrypted-object cases.
Discovery initially excludes the siblings. Normal publication on this host creates
an exact canonical sibling, then retry returns `ALREADY_PRESENT_EXACT` with a
fail-on-durability callback. Ordinary discovery accepts that exact filename and
core authenticates the real TOKEN. Alias bytes, file identity, and modification
time remain unchanged. Existing read-only exact-existing, unreadable/non-exact,
concurrent publication, and vault workflow tests remain in the full suite.

Under the original aliasing model, uppercase-only objects yield no exact target.
A no-replace link collides; re-enumeration still finds no exact target, so publication
fails before comparison. Uppercase-only VAULT yields canonical absence, replacement
fails for lack of an exact target, and initial link collision cannot overwrite it.
Uppercase-only namespace lookup yields no exact namespace; mkdir collision with
no exact winner fails before recursion or publication. These paths remove the
original three alias-to-canonical transitions under ordinary provider semantics.

The review's temporary provider probe was not available in this environment.
A full forwarding aliasing NIO provider would require substantial test machinery;
it was not added. Pure selection, existing fault seams, real case-sensitive
filesystem regressions, and source reasoning provide this remediation evidence.
They are **not qualification of an actual case-insensitive provider**.

## F2 — hostile filename hash amplification

`DiscoverySource.Snapshot` already sorted candidates by canonical filename, then
inserted unauthenticated ObjectIds into a HashSet. IDs made from `(0,31)` and `(1,0)`
byte pairs share `Arrays.hashCode`, making that redundant non-comparable hash-key
structure susceptible to hostile collision amplification.

The sorted list now rejects duplicates through adjacent exact ObjectId equality.
Ordering, duplicate rejection, SPI contract, and candidate limits are unchanged;
no Comparable implementation or arbitrary count limit was added. Duplicate
checking takes n-1 equality comparisons after the existing sort, independent of
attacker-selected Java hashes.

`DiscoverySourceTest` constructs 16,384 distinct colliding IDs, independently checks
both byte-array and ObjectId hash equality, checks strict sorted distinctness,
verifies deterministic results after input reversal, rejects an added duplicate,
and ensures no opener runs. It uses an ordinary test timeout, not a timing threshold.

Collection audit: NioDiscoverySource candidates and TokenStoreObservation/reader
diagnostics use lists, with no equivalent pre-authentication hash deduplication.
The Snapshot HashSet was removed. Graph maps/sets operate on validated facts;
publication-plan parent deduplication is explicit caller-authorship input, not
hostile directory discovery. VAULT stage sets hold internal stage identities.
Those unrelated/authenticated structures were left unchanged.

## F4 — secret formatting and lifetime

`SecurityBytes.toString()` now always returns `SecurityBytes[redacted]`, without
bytes, length, hash, prefix, digest, Base64, or hex. Content equality and hashCode
remain unchanged for immutable credential/value collections.

Direct tests compare one-byte secrets 0 and 1 and a 128-byte secret, assert the
same safe string, exclude their hexadecimal content-derived hashes, and preserve
value equality/hash semantics. Existing TokenValue, Credential, TokenObject, and
VaultUnlockResult formatting tests remain. Production audit of these five types
found no remaining content-derived secret string: the three containing TOKEN types
redact, and VaultUnlockResult prints only status. No logging cleanup was needed.

Credential/session lifetime remains an API-design input. Immutable SecurityBytes
and TokenValue credentials remain retained by graphs/plans and are not wipeable.
Closing the owned root result does not wipe all credential copies. This milestone
only repairs formatting; it does not create mutable wipeable hash keys or promise
session-wide erasure.

## F5/F6 — current documentation and qualification limits

`SPEC_PIN.md` now records the unchanged r17 pin and 90/90 implemented portable
cases, with no deferred categories; it distinguishes integrity from semantic
coverage and makes no release claim. The four missing historical report links
were removed from README. Its implementation evidence now points to the tracked,
executable Phase2ConformanceTest. Local Markdown destination checks for README and
SPEC_PIN passed; no remaining README implementation-evidence link is missing or
untracked. The untracked review/remediation reports are not assumed to be published
link targets.

The ten identified current-looking production r16 comments now say v1. ObjectId
and V1EnvelopeWriter use stable section-neutral wording. README explicitly says
independent interoperability has not been demonstrated and corpus completion does
not establish API stability, release readiness, desktop/Android completion, provider
qualification, or universal power-loss behavior.

README documents full-suite assumptions: case-sensitive filesystem, symlinks,
hard links, atomic existing-target moves where tested, directory-channel force,
POSIX permissions, and mkfifo/POSIX fixtures. These are integration environment
assumptions, not all protocol requirements. Existing optional provider fixture
assumptions remain visible; normative 90-case conformance must never silently skip.
No conformance test was converted to an environment assumption.

Actual execution here: Linux, local case-sensitive filesystem, OpenJDK Nix
25.0.4.1, Gradle 9.8.0. Only these local provider capabilities and injected failures
were exercised. Windows, macOS, Android, actual case-insensitive providers, broader
providers, and physical crash/power-loss qualification remain open.

## F3 — explicit public-API blocker

**F3 remains intentionally unresolved pending public API design.**
VaultUnlockResult still mixes cryptographic facts with ABSENT/UNAVAILABLE storage
observations; lifecycle FAILED still combines known pre-attempt failure with
ambiguous post-attempt persistence. These are real design inputs, not current r17
correctness failures. Before public API freeze, design must separate:

- Cryptographic unlock result.
- Storage observation state.
- Lifecycle operation outcome.
- Persistence certainty.

No signatures or stable result taxonomy are proposed here. Both orchestration
types remain package-private. A short comment warns that FAILED does not prove
canonical bytes unchanged; the misleading storage-free result comment now calls
out provisional storage statuses. No certainty was erased, ambiguous failure was
not reclassified, and no rollback/success behavior changed. Public API design may
begin as a separate milestone, with F3 and credential lifetime explicit blockers
to freezing the API. It was not begun here.

## Exact production scope and accounting

45 production Java files remain; physical production LOC (including comments and
blank lines) changed from **2,255 to 2,288**, net +33. Twenty production files changed:

```text
core/src/main/java/dev/totipo/format/CryptoSupport.java
core/src/main/java/dev/totipo/format/DiscoverySource.java
core/src/main/java/dev/totipo/format/ObjectId.java
core/src/main/java/dev/totipo/format/PasswordBytes.java
core/src/main/java/dev/totipo/format/SecurityBytes.java
core/src/main/java/dev/totipo/format/TlvReader.java
core/src/main/java/dev/totipo/format/TokenGraph.java
core/src/main/java/dev/totipo/format/TokenReader.java
core/src/main/java/dev/totipo/format/TokenValue.java
core/src/main/java/dev/totipo/format/TokenWriter.java
core/src/main/java/dev/totipo/format/V1EnvelopeWriter.java
core/src/main/java/dev/totipo/format/VaultBootstrap.java
core/src/main/java/dev/totipo/format/VaultBootstrapWriter.java
core/src/main/java/dev/totipo/format/VaultLifecycle.java
core/src/main/java/dev/totipo/format/VaultUnlockResult.java
core/src/main/java/dev/totipo/format/VaultUnlocker.java
storage-nio/src/main/java/dev/totipo/storage/nio/NioDiscoverySource.java
storage-nio/src/main/java/dev/totipo/storage/nio/NioFiles.java
storage-nio/src/main/java/dev/totipo/storage/nio/NioV1ObjectPublicationStore.java
storage-nio/src/main/java/dev/totipo/storage/nio/NioVaultBootstrapStorage.java
```

Only DiscoverySource, SecurityBytes, and the four listed NIO files have behavioral
changes. Fourteen other production files have comment-only changes. No new
production source, external/test dependency, native code, filesystem library,
database, journal, generation counter, or provider-specific protocol was added.

## Final validation

The full clean build and isolated offline rerun passed **312 tests: 256 core +
56 storage-nio, zero failures/errors/skips**, an increase of 15 regression test
invocations. All **90/90 portable corpus cases** still execute; no category is
deferred and no corpus case was edited. Separate module clean/test invocations
also passed (their test results were restored from the valid Gradle build cache;
the offline rerun explicitly disabled that cache and reran all 16 tasks).

Runtime dependency trees remain exactly core → BC `bcprov-jdk18on:1.86` and
storage-nio → core → transitive BC 1.86. No build/lock/verification inputs changed.
Both production bytecode verification tasks passed: all classfiles major **61**,
minor 0, with `--release 17` unchanged. Tests ran on JDK 25; execution on JDK 17
itself was not newly qualified.

The pinned snapshot diff is empty; all **97/97 checksum records** passed again.
The review SHA-256 remains identical to the starting value. README/SPEC_PIN local
Markdown links resolve to tracked files. `git diff --check` passed.

Required commands executed, with no overlapping Gradle invocations:

```sh
./gradlew clean test build
./gradlew :core:clean :core:test
./gradlew :storage-nio:clean :storage-nio:test
./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test
./gradlew :core:dependencies --configuration runtimeClasspath
./gradlew :storage-nio:dependencies --configuration runtimeClasspath
./gradlew :core:verifyJava17Bytecode :storage-nio:verifyJava17Bytecode
./gradlew :storage-nio:test \
  --tests '*NioExactNameTest' --tests '*NioPublicationTest' \
  --tests '*NioVaultStorageTest' --tests '*NioDiscoveryTest' \
  :core:test --tests '*DiscoverySourceTest' --tests '*SecurityBytesTest' \
  --tests '*TokenCodecTest' --tests '*TokenNioWorkflowTest' \
  --tests '*StorageVectorTest' --tests '*VaultVectorTest' \
  --tests '*BootstrapVectorTest' --tests '*VaultNioWorkflowTest' \
  --tests '*Phase2ConformanceTest' --tests '*SpecSnapshotIntegrityTest' \
  --tests '*R17ProfileIntegrityTest'
(cd core/src/test/resources/totipo-spec/v1-pre-rc && sha256sum -c SNAPSHOT.sha256)
git diff -- core/src/test/resources/totipo-spec/v1-pre-rc
git diff --check
```

The baseline additionally ran focused SpecSnapshotIntegrityTest and
R17ProfileIntegrityTest before editing. An initial focused regression run also
passed before the final namespace/initial-install collision tests were added.
The complete final suites include those additions. Command logs are temporary
local evidence under `/tmp/r17-*`; this report records their outcomes rather than
depending on untracked historical reports or permanent external log links.
The final targeted command passed **132 tests (87 core + 45 storage-nio), zero
failures/errors/skips**, including the executed 90-case inventory. Its smaller
JUnit count reflects the selected test classes; the full-suite total remains 312.

Unresolved work is limited here to F3/API outcome separation, credential/session
lifetime design, broader and actual case-insensitive provider qualification,
independent interoperability, and broader crash/power-loss evidence. Exact-name
enumeration adds directory-scan cost; this milestone adds no resource-budget API.
No claim of universal provider portability or complete credential erasure is made.
No commit, push, tag, release, or public API design was performed.
