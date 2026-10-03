# Totipo Java v1/r18 repin report

## Summary

`totipo-java` was repinned from Totipo Vault Format v1/r17 to committed v1/r18.
No portable implementation-semantic behavior changed. All 90 cases remain
byte-identical and pass under both pins. Production Java edits are Javadoc only.

This is a repin/conformance-documentation change. The library claims core and store
conformance only for the operations identified below; it does not claim application
conformance. At repin time, a facade historical-metadata scope question and application
observation limitations were flagged for human review, without an API redesign.
The subsequent [focused §12 audit](V1_R18_CAUSAL_FACT_METADATA_REPORT.md) resolves
the historical-metadata question; application-observation limitations remain. No commit, tag, release, push, signing or external publication was performed.

The starting worktree contained an untracked report about the earlier upstream
profile defect. This report supersedes that blocked audit: upstream committed the
repair before this run. The prior report was preserved locally at
`/tmp/totipo-r18-prior-blocked-report.md`.

## Exact specification pin

- Repository: https://github.com/totipo-org/totipo-spec
- Exact committed r18 pin: `4623a7e1718e23504903096c92332597057bd8f0`.
- Commit subject: `repair r18 profile integrity pin and validate artifact hashes`.
- Normative revision: `r18`; protocol version remains `1`.
- Release/tag: **no r18 release or tag exists** in the remote refs and GitHub release
  inventory checked during this run. The only observed historical tag/release is
  `v0-rc1`. The authoritative pin is the exact SHA, not a moving branch.
- Exact r17 baseline pin: `1d42a481f230e0adbb89dbeaa936d3c956e70fdc`.

Computed from exact committed blobs, then separately checked with `sha256sum` in
the upstream checkout:

| Artifact | r18 SHA-256 |
| --- | --- |
| `spec/totipo-vault-format-v1.md` | `8a357e75f3ddd92efa954fde2ffc9af33f40a2c2396d6afbf1d5de5f00bc4f8a` |
| `vectors/manifest.json` | `bd2b52adc05b26e09790f5f7367761b2b86ba3cf8d97d10ed187fcf7213fcf02` |
| `vectors/manifest.schema.json` | `f6dfef831f9b391ef8c9e675024b9cb9cb6cc352858c182439ee8847e55c3647` |
| `vectors/case.schema.json` | `d38618f53dcf0a558c389831e8838a07248066beff392812f3d277cc974e25c9` |
| `requirements/v1-pre-rc.json` | `4c7954cd2b59aa0afbbe3c22080cadddf72135d884b186a671266c29d58418df` |
| `vectors/FORMAT.md` | `776f5f33231c43fa9d5da10c2eb4792cda7f7b5c8cef93902f140239c763012f` |
| `LICENSE` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

The initial r18 commit `43f3bf9c330054d62e7e263444acf6988dbcae35` had a stale
profile `spec_sha256`. The selected repair commit retains the same normative r18
bytes and fixes that cross-pin. No hash from the earlier draft/report was trusted;
all four profile artifact cross-pins now match the committed files.

## r17 → r18 assessment

The full normative-file diff was reviewed independently of upstream's unchanged-
semantics statement. Sections 1, 2, 4, 6, 9, 10, 11, 14, 18 and 19 are
byte-identical. Changed normative sections contain the following application or
editorial changes; no portable protocol requirement changed.

| r18 change | Java action and evidence |
| --- | --- |
| Conformance scopes (§20) | Documentation: identify supported core/store operations and qualification limits; no application claim or blanket facade core claim. |
| Missing vault / possible orphan evidence (§§3, 7) | API documentation: creation still permitted, no exhaustive enumeration or name-based veto. `ApplicationVaults.create` does not scan before installation; NIO workflow and corpus orphan cases pass. SPI callers may observe names before handing off ownership. No implementation change. |
| Empty-password confirmation (§5) | Documentation: interactive application MUST confirm creation; empty UTF-8 remains accepted for readers and creation. `VaultLifecycleTest.emptyPasswordCreationAndMaxLengthUtf8AreProtocolInputs` and public API empty-input paths pass. No reader/policy change. |
| Tombstone / erasure disclosure (§16) | Documentation/Javadoc: complete tombstones retain SECRET_BYTES; deletion is not secure erasure of history/provider copies. Encoding and TOTP remain unchanged. |
| Password-rewrap disclosure (§8) | Documentation/Javadoc: same K_root, fresh salt/nonce, no old-wrapper revocation, rollback protection or full security reset. Existing lifecycle/fingerprint/rewrap tests pass. |
| Root-compromise guidance (§8.1) | No implementation change; informative guidance defines no migration/re-key protocol. API docs clarify the boundary. |
| Cycle clarification (§15) | No Java change; iterative bounded SCC traversal and abstract-cycle interpretation remain required and tested. |
| Same-ID clarification (§13) | No Java change; contradictory valid objects still excluded and references remain unresolved. Informative collision discussion does not relax validation. |
| Metadata references (§§12, 15–17) | Documentation: exact retention was already required. Codec/models/graph/fold/exposed heads preserve it; the subsequent focused §12 audit resolves historical facade causal-fact retention as a derived index. No wire/equality/fold change. |
| Historical cleanup (§21) | No implementation change. Exact upstream spec archives r1–r15 details to upstream review material; Java's existing historical reports remain untouched. The archive is outside the established 97-file snapshot. |

Explicit portable invariants checked:

| Invariants | Evidence / result |
| --- | --- |
| VAULT/bootstrap bytes; Argon2id parameters; HKDF/HMAC/AES-GCM; domain strings; VAULT_FINGERPRINT; OBJECT_ID; object key/nonce/AAD | §§4, 6, 9–11 unchanged byte-for-byte. |
| Password UTF-8 domain and 1024-byte bound | §5 changes only interactive confirmation/disclosure. Empty UTF-8 remains valid. |
| Fixed 1024-byte envelope; semantic length/padding | §11 unchanged. |
| TOKEN tags/order/widths; MAX_PARENTS=4; maximum size/capacity; metadata wire form; sorted/duplicate-free parents | §12 only consolidates metadata retention prose; grammar, limits and 1005-byte maximum unchanged. |
| Same-ID exclusion; unresolved parents | §13 adds only an informative note; §14 unchanged; defensive semantics unchanged. |
| Causal equivalence/SCC; current heads | §15 adds informative cycle note and metadata cross-reference; normative algorithm unchanged. |
| TokenValue equality; complete tombstone including secret | §16 adds application erasure disclosure and metadata cross-reference; protocol unchanged. |
| Bounded fold | §17 consolidates operation-wide metadata wording; stages, parents and fold construction unchanged. |
| Immutable publication | §18 byte-identical. |
| Password rewrap | §8 preserves same K_root and fresh salt/nonce; adds disclosure and informative recovery guidance. |
| TOTP; supported algorithms/digits/period/secret | §19 byte-identical; §12 parameter grammar unchanged. |


No TOKEN inputs, expected outputs, domain-separation constants, or protocol
fixtures were regenerated. All protocol foundation and NIO implementation bodies
remain unchanged.

## Conformance claims

The current README, API design, SPI design, release checklist and relevant Javadocs
make these operation-scoped claims:

| Scope | Claimed modules / operations / limits |
| --- | --- |
| v1 core conforming | `core` protocol foundation: bootstrap reading/creation/rewrap; object crypto/identity; TOKEN encoding/validation and exact per-object metadata; graph/current-state evaluation; complete-value equality; bounded folds; TOTP. These protocol models/operations retain metadata. The subsequent focused §12 audit includes audited facade TOKEN projections and create/update/merge metadata handling; no blanket certification of every facade operation. |
| v1 store conforming | `storage-nio` with low-level core observation/publication/VAULT orchestration: observation, immutable publication, no-replace initial creation, replacement with exact compare-before-replace, required-byte preservation and explicit durability outcomes. Core authenticates and compares; the SPI does not interpret protocol bytes. Qualified only by the tested local case-sensitive Linux provider capabilities. |
| v1 application conforming | **Not claimed.** A reusable library exposes facts but does not implement interactive UI confirmation, warnings, truthful presentation, relevant-alternative disclosure or safe untrusted-text rendering. |

Abstract workflow tests, successful force calls and reopen tests do not prove
physical power-loss behavior on all filesystems/providers. Other platforms,
independent interoperability and production security auditing remain unqualified.

### Metadata and application API audit

`TokenReader` uses strict UTF-8 without normalization. `TokenMetadata` and
`ClientMetadata` preserve optional name presence, present-empty versus absent,
exact validated text, optional time presence, zero and all unsigned u64 values.
`ApplicationSession.metadata` maps time through `UInt64.rawBits`; negative Java
longs retain unsigned high-bit values (including unsigned maximum as `-1L`).
`TokenCodecTest` exercises byte round trips, empty/absent names, absent/zero time,
unsigned boundaries, NUL, combining text and supplementary Unicode. `TokenGraphTest`
and `TokenFoldTest` preserve each object's metadata and operation-wide fold metadata.
Exposed and previously captured `TokenHead` instances retain exact metadata even
when equal-valued heads are grouped by semantic value.

**Subsequent §12 audit resolution:** The
[focused CausalFact audit](V1_R18_CAUSAL_FACT_METADATA_REPORT.md) resolves the scope
question identified at repin. `ApplicationSession.CausalFact` retains causal/topological
facts derived from a validated TOKEN but does not retain or represent that TOKEN
object itself. Only merge containment consumes these links; no historical object
or metadata presentation derives from them. Actual current/captured heads retain
exact metadata independently. No production semantic fix was required. The previous
historical-metadata qualification is removed, and audited facade TOKEN projections
and create/update/merge metadata handling (including partial resolution/frozen retries)
are included in the corresponding core operations. Application-observation limitations
and the absence of blanket facade/application certification remain.

| Application fact | Existing support / limitation |
| --- | --- |
| Empty-password creation intent | Caller owns the supplied `char[]` and knows it is empty. No library dialog; empty-password reading remains valid. |
| Possible orphan-looking entries | Before transferring ownership, SPI `readVault`/`scanObjects` expose observed names and incomplete observation. Exactly 64 lowercase-hex names supply unauthenticated context regardless of kind. `NioTotipo.create` itself has no pre-creation orphan context/result: flag facade diagnostic needs for human review. No exhaustive scan requirement or veto added. |
| Current vs historical/stale | Immutable states expose current observed head IDs; callers can compare captured heads with later observations. Missing evidence/rollback cannot certify globally freshest state or prove historical supersession. |
| Conflicts and equal distinct heads | `hasConflict` distinguishes distinct complete values; alternatives group equal values while retaining all distinct heads and metadata. |
| Tombstone | Descriptor status is explicit; complete credential and TOTP remain usable. It is logical deletion, not erasure. |
| Missing ancestry / unavailable | `unresolvedReferences`, observation progress and diagnostics expose known gaps. Facade diagnostics lack arbitrary candidate identity; SPI names/read outcomes supply lower-level detail. Per-object unavailable attribution through the facade is a human-review limitation. |
| Complete-known vs unavailable | Represented alternatives have validated complete values; missing/unreadable objects have no fabricated complete value. Retained alternatives remain session-backed capabilities. |
| Newly learned relevant alternatives | Merge reobserves; `SaveResult.AdditionalConflict` returns latest state and a partial-resolution choice, including newly learned equal-valued distinct heads. Application performs disclosure/decision. |
| Exact metadata | Every represented public head has exact optional name and optional u64 bits; the subsequent §12 audit establishes that causal facts are derived indexes, not retained objects. |
| Rewrap semantics/results | `PasswordChangeResult` distinguishes CHANGED/AUTHENTICATION_FAILED/STALE/FAILED/UNCERTAIN. Same root with fresh salt/nonce; old wrappers remain usable. |

No application-specific UI, policy, dialog or new API surface was added.

## Snapshot/integrity changes

The established `core/src/test/resources/totipo-spec/v1-pre-rc/` layout is preserved:
90 cases and seven upstream supporting files, with a sorted 97-record checksum
inventory excluding itself. Each original file first matched the exact r17 blob;
each final file matches the exact committed r18 blob. Only five supporting files
needed replacement; cases were not rewritten.

| Updated artifact | r17 SHA-256 | r18 SHA-256 |
| --- | --- | --- |
| `requirements/v1-pre-rc.json` | `ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e` | `4c7954cd2b59aa0afbbe3c22080cadddf72135d884b186a671266c29d58418df` |
| `spec/totipo-vault-format-v1.md` | `f8d2ab02c97e8ac54847048a06cb088359db982fec3f176fd473ce0f223d43cf` | `8a357e75f3ddd92efa954fde2ffc9af33f40a2c2396d6afbf1d5de5f00bc4f8a` |
| `vectors/FORMAT.md` | `0ddaf84ff214a0859abd29f1f104792854940f25ec87f5dc849ca3b3d84d8a74` | `776f5f33231c43fa9d5da10c2eb4792cda7f7b5c8cef93902f140239c763012f` |
| `vectors/manifest.json` | `94fff22842573e15b254bb0653970761c15cf122192947a36fccc48344a84f08` | `bd2b52adc05b26e09790f5f7367761b2b86ba3cf8d97d10ed187fcf7213fcf02` |
| `vectors/manifest.schema.json` | `e7a5d8ec0392e0248ab867375b7c907a7ca1298595acdb14ecd3edcbe66df476` | `f6dfef831f9b391ef8c9e675024b9cb9cb6cc352858c182439ee8847e55c3647` |

Case-schema and LICENSE hashes are unchanged (exact hashes above). All 90 case
hashes and checksum records are unchanged. `SNAPSHOT.sha256` itself changes from
`08e9e85f7b3ae048913136b83c33e6cdaf3ebc0b898a906420f4ec64ed26a526` to
`8f480777b5fa1f3214c9baf1a352fce0ecd60a2787c893a4521e0af9962ebbe2`.
It remains an inventory, not a self-referential independent pin.

`SPEC_PIN.md` records the new revision, exact source SHA, tag status, import time
and hashes. `SpecSnapshotIntegrityTest` updates four independently hard-coded
artifact pins; its unchanged case-schema pin remains. It additionally checks
`SPEC_PIN.md` against an independently hard-coded source commit and revision.
All malformed-path, duplicate, symlink, changed/missing/uncovered-file checks remain.
Expected values are not derived from the snapshot being checked.

`R17ProfileIntegrityTest` becomes `R18ProfileIntegrityTest`; all 90-case, physical
coverage, schema/manifest/profile hash cross-checks remain intact. Only the class
name and expected revision change. Manifest schema pins r18; required case IDs,
order, hashes and outcomes are unchanged. No corpus skip/capability mechanism added.

## Corpus compatibility

| Audit item | Result |
| --- | --- |
| Case count | 90 → 90 |
| Case IDs and order | Identical; full ordered manifest `cases` arrays equal. |
| Case paths/metadata/hashes | Identical; all manifest entries equal except top-level revision. |
| Physical case bytes | All 90 byte-identical to exact r17 and r18 blobs; not rewritten. |
| Expected outcomes | Identical, proven by byte comparison and executed test results. |
| Profile required cases | Full ordered `required_cases` arrays identical. |
| r17 execution | 90/90; no skips or deferrals. |
| r18 execution | 90/90; no skips or deferrals. |
| Other protocol fixture bytes | No changes; complete diff/source inspection confirms this. |

`Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping` accounts for
90 cases only after all assertions execute successfully. Category counts remain:
bootstrap 4, crypto 5, encoding 30, fold 6, graph 13, metadata 7, size 1, storage 13,
TOTP 3, vault 8.

Baseline and r18 JUnit inventories have identical test method identities and
pass outcomes after normalizing the profile test's r17/r18 class rename. Both have
346 core tests and 115 NIO tests, zero failures/errors/skips. All 88 compiled
`org.totipo.format` protocol classes are byte-identical; 199 of 202 production
class hashes match overall. The three changed class hashes correspond to
comment-edited public classes; production source token comparison proves code
bodies unchanged. No protocol-semantic source changes were found.

## Java implementation changes

**None.** No semantic production source, method body, public signature, parser,
crypto, graph, fold, TOTP, publication state machine, storage behavior, metadata
model, tombstone or password-rewrap behavior changed. Five production source files
have Javadoc-only edits; one API test has a revision-comment edit. Integrity-test
constants/revision assertions and documentation are updated separately.

Final safeguards confirm empty-password readability, orphan-tolerant creation,
unchanged tombstone SECRET_BYTES, same-root rewrap, bounded cycle-safe traversal,
same-ID exclusion, and exact metadata in the claimed protocol operations/public
heads. The historical-facade metadata question recorded at repin is now resolved
by the subsequent focused §12 audit above. The repin's validation/diff evidence
below remains historical evidence of that earlier change.

## Validation

JDK 25.0.4.1 and the pinned Gradle 9.8.0 wrapper were used. Java production remains
`--release 17`. Local Maven staging is credential-free package validation; it does
not upload or release anything.

| Command / check | Result |
| --- | --- |
| `git clone https://github.com/totipo-org/totipo-spec.git /tmp/totipo-spec-r18-current`; exact `git log`, `git show`, `git diff <r17> <r18>`, `git ls-remote --heads --tags origin` | PASS: exact committed repaired r18 source and absence of r18 tag verified. |
| `curl -fsSL https://api.github.com/repos/totipo-org/totipo-spec/releases` | PASS: only historical v0-rc1 release returned. |
| Python `subprocess`/`hashlib`/`json` exact-blob and ordered corpus comparison | PASS: 97/97 baseline and final files match their exact commits; 90 IDs/order/bytes/hashes/outcomes unchanged; profile cross-pins consistent. |
| `sha256sum` on the seven upstream supporting files | PASS: independently confirms all exact r18 hashes above. |
| `python3 tools/check_spec.py` in upstream checkout | PASS: r18 structure and profile artifact hashes. |
| `sha256sum -c SNAPSHOT.sha256` in snapshot directory | PASS: all 97 imported files. |
| `./gradlew clean test build` before edits (r17 baseline) | PASS: 461 tests, no failures/errors/skips; 90/90 portable cases; SpecSnapshotIntegrityTest 3/3; Java-17 checks, strict dependency checks, binary/source/Javadoc JARs. |
| `./gradlew clean test build verifyPublication consumerSmoke` after repin | PASS: same 461 tests and 90/90 corpus; SpecSnapshotIntegrityTest 3/3 and R18ProfileIntegrityTest pass; package inventory and module-metadata standalone consumer pass. |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test build verifyPublication consumerSmoke` | PASS: all 30 root tasks executed without build cache; 461 tests, zero failures/errors/skips; 90/90 corpus; snapshot/profile integrity, build/package and standalone consumer pass. |
| `../gradlew :core:test --tests org.totipo.conformance.SpecSnapshotIntegrityTest` from `core/` | PASS: SpecSnapshotIntegrityTest 3/3, zero failures/errors/skips; no missing-file error. |
| `./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check` | PASS: POM-only consumer compile/runtime dependency boundaries verified. |
| Two clean r18 `build/publication-sha256.json` inventories compared | PASS: all 10 artifact hashes identical (six JARs, two POMs, two module files), in the same environment. |
| Production Java comment-aware token comparison with HEAD; fixture/case diff audit; JUnit inventory/class-hash comparison | PASS: no semantic source or fixture/case changes; test identities/results equal; all 88 protocol class hashes equal. |
| `git diff --check`; complete tracked diff and renamed integrity-test inspection | PASS. |
| `command -v nix` | Unavailable; Nix build/check not run. |

Ordinary root Gradle execution runs tests with the core project as working
directory; integrity tests successfully locate both snapshot and `SPEC_PIN.md`.
The separate invocation from `core/` also passed all three integrity tests.
No `NoSuchFileException` occurred, and no check/path bypass was needed. The test's independent pins and negative integrity checks were preserved.

Normal validation includes unit/integration/conformance, crypto/vector, graph/fold,
TOTP, lifecycle, store/NIO, race/concurrency and API suites. Compiler
`-Xlint:all -Werror`, strict dependency verification and both Java-17 classfile checks
pass. No separate Java formatter/linter/static-analysis task is configured.
Existing missing-Javadoc/comment warnings remain; Javadoc generation succeeds.
No normal build regenerates portable fixtures.

Not run: Nix build/check (unavailable), other-platform qualification and physical
power-loss testing, independent interoperability/security audits. No signing,
Central upload or release tasks were run, as instructed.

Local evidence: `/tmp/totipo-r17-baseline.log`, `/tmp/totipo-r18-validation.log`,
`/tmp/totipo-r18-offline.log`, baseline/r18 core and NIO JUnit copies under
`/tmp/totipo-r17-*-results` and `/tmp/totipo-r18-*-results`, and exact comparison
inventories under `/tmp/totipo-r18-*.json`. These temporary files are execution
evidence and are not added to the repository.

## Packaging

Gradle build/package checks and credential-free staged Maven consumer tests pass.
Both artifacts preserve Java 17 production bytecode, exact dependency boundaries
and exclusions for specification resources/tests/test fixtures. Gradle wrapper,
dependency locks, verification metadata, CI and package scripts have no stale
spec pin and require no change.

`VERSION` remains **0.1.0**. No maintained next-version field or required in-tree
increment workflow was found; the existing `v0.1.0` source tag was not modified.
Documentation distinguishes the current r18 worktree from its prior r17 target.
A follow-up reviewed patch release would likely be **v0.1.1**, described as:
“Repin to Totipo Vault Format v1/r18; no portable protocol behavior change.”
No release was prepared or performed.

Nix is unavailable. `flake.nix` supplies development shells and a formatter,
with no package/check output or spec/resource hash pin. No r18-driven flake/lock
change is needed; no Nix build/check is claimed.

## Revision-reference classification

Current references in README, SPEC_PIN, API/SPI design, release checklist, integrity
tests and the API-test pinned-record comment were updated. The exact imported
normative spec retains its authentic r17 comparison and revision-history entries.
Prior Java review reports accurately describe r17 work and were preserved.
Remaining r17 mentions in current docs describe the actual prior pin/transition.
All old current pin hashes were removed from active pin consumers; historical
hashes in review evidence remain historical. No ambiguous generic full-conformance
claim was retained or introduced in authored current library documentation.
The normative snapshot's scope language is imported unchanged from upstream.

## Files changed

| Path | Reason |
| --- | --- |
| `API_DESIGN.md` | Current r18 target, scoped claims, exact metadata and application API support/limitations. |
| `README.md` | Current r18 target, operation-scoped core/store claims, no application claim, release/version distinction. |
| `RELEASE_CHECKLIST.md` | Current r18 provenance and scope review gates; version remains 0.1.0. |
| `SPEC_PIN.md` | Exact repaired r18 source SHA, tag status, timestamp and independent artifact hashes. |
| `SPI_DESIGN.md` | Current r18 target and qualified store/application boundary. |
| `core/src/main/java/org/totipo/ClientMetadata.java` | Javadoc: exact name presence/text and unsigned time bits. |
| `core/src/main/java/org/totipo/TokenEditor.java` | Javadoc: tombstoning retains secrets/history and is not secure erasure. |
| `core/src/main/java/org/totipo/Totipo.java` | Javadoc: application responsibilities and optional pre-creation SPI observation. |
| `core/src/main/java/org/totipo/VaultSession.java` | Javadoc: same-root password rewrap, fresh salt/nonce, security limits. |
| `storage-nio/src/main/java/org/totipo/storage/nio/NioTotipo.java` | Javadoc: interactive responsibilities and pre-creation diagnostic limitation. |
| `core/src/test/java/org/totipo/api/PublicApiTest.java` | Current-pin comment r17 → r18; assertions unchanged. |
| `core/src/test/java/org/totipo/conformance/R17ProfileIntegrityTest.java` | Deleted old filename as part of rename; no checks removed. |
| `core/src/test/java/org/totipo/conformance/R18ProfileIntegrityTest.java` | Added renamed integrity test; only class name and expected revision change. |
| `core/src/test/java/org/totipo/conformance/SpecSnapshotIntegrityTest.java` | Updated four independent artifact hashes; added independent exact source SHA and revision cross-checks. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/SNAPSHOT.sha256` | Five updated supporting-file records; all 90 case records and layout unchanged. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/requirements/v1-pre-rc.json` | Exact committed r18 profile, including repaired spec hash; required_cases unchanged. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/spec/totipo-vault-format-v1.md` | Exact committed r18 normative specification, including editorial history cleanup. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/vectors/FORMAT.md` | Exact committed r18 portable-case guide; revision wording only. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/vectors/manifest.json` | Exact committed manifest; only spec_revision changes. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/vectors/manifest.schema.json` | Exact committed manifest schema; only revision constant changes. |
| `review/V1_R18_REPIN_REPORT.md` | Updated the pre-existing untracked blocked audit with completed repin evidence and review qualifications. |

No other files were changed. Renaming the profile test appears as a deletion and
an untracked addition until reviewed/staged. No file was staged by this task.

## git diff --stat

```text
 API_DESIGN.md                                      |  61 ++-
 README.md                                          |  39 +-
 RELEASE_CHECKLIST.md                               |  20 +-
 SPEC_PIN.md                                        |  37 +-
 SPI_DESIGN.md                                      |  20 +-
 core/src/main/java/org/totipo/ClientMetadata.java  |   4 +-
 core/src/main/java/org/totipo/TokenEditor.java     |   2 +
 core/src/main/java/org/totipo/Totipo.java          |   4 +
 core/src/main/java/org/totipo/VaultSession.java    |   4 +-
 .../test/java/org/totipo/api/PublicApiTest.java    |   2 +-
 .../conformance/R17ProfileIntegrityTest.java       |  75 ----
 .../conformance/SpecSnapshotIntegrityTest.java     |  16 +-
 .../totipo-spec/v1-pre-rc/SNAPSHOT.sha256          |  10 +-
 .../v1-pre-rc/requirements/v1-pre-rc.json          |   8 +-
 .../v1-pre-rc/spec/totipo-vault-format-v1.md       | 466 +++++++--------------
 .../totipo-spec/v1-pre-rc/vectors/FORMAT.md        |   4 +-
 .../totipo-spec/v1-pre-rc/vectors/manifest.json    |   2 +-
 .../v1-pre-rc/vectors/manifest.schema.json         |   2 +-
 .../java/org/totipo/storage/nio/NioTotipo.java     |   6 +-
 19 files changed, 325 insertions(+), 457 deletions(-)
```

This is ordinary unstaged `git diff --stat`; it excludes the two untracked files
(the renamed r18 test and report) listed below. The apparent 75-line test deletion
is a rename with only class/revision changes, not removal of integrity coverage.

## git status --short

```text
 M API_DESIGN.md
 M README.md
 M RELEASE_CHECKLIST.md
 M SPEC_PIN.md
 M SPI_DESIGN.md
 M core/src/main/java/org/totipo/ClientMetadata.java
 M core/src/main/java/org/totipo/TokenEditor.java
 M core/src/main/java/org/totipo/Totipo.java
 M core/src/main/java/org/totipo/VaultSession.java
 M core/src/test/java/org/totipo/api/PublicApiTest.java
 D core/src/test/java/org/totipo/conformance/R17ProfileIntegrityTest.java
 M core/src/test/java/org/totipo/conformance/SpecSnapshotIntegrityTest.java
 M core/src/test/resources/totipo-spec/v1-pre-rc/SNAPSHOT.sha256
 M core/src/test/resources/totipo-spec/v1-pre-rc/requirements/v1-pre-rc.json
 M core/src/test/resources/totipo-spec/v1-pre-rc/spec/totipo-vault-format-v1.md
 M core/src/test/resources/totipo-spec/v1-pre-rc/vectors/FORMAT.md
 M core/src/test/resources/totipo-spec/v1-pre-rc/vectors/manifest.json
 M core/src/test/resources/totipo-spec/v1-pre-rc/vectors/manifest.schema.json
 M storage-nio/src/main/java/org/totipo/storage/nio/NioTotipo.java
?? core/src/test/java/org/totipo/conformance/R18ProfileIntegrityTest.java
?? review/V1_R18_REPIN_REPORT.md
```

## Release assessment

Suitable for human review as a small r18-alignment patch change: exact repaired
committed pin, unchanged portable semantics/corpus and passing Java/package
validation. Release suitability is limited to the documented operation-scoped
claims and existing provider qualifications. The subsequent focused §12 audit
resolves the historical-facade metadata qualification without a semantic fix;
application-observation limitations remain. Neither audit certifies every facade
operation or application conformance.
Version selection, committing, signing, tagging and publishing remain future
operator work. No unexpected semantic change was found in the final diff.
