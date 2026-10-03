# v0.1.1 release-preparation report

## Summary

The worktree is prepared for proposed `v0.1.1`, aligned to Totipo Vault Format
v1/r18. Repin to Totipo Vault Format v1/r18; no portable protocol behavior change.
All changes remain uncommitted for human review. Validation stages unsigned
artifacts only in the ignored local `build/repository`; no external release action
was performed.

## Baseline

- Starting committed HEAD: `7b493d17be2438b9a2b3340a0791fdeb545e66b2`
  (`clarify causal fact metadata semantics and facade conformance`).
- Prior committed repin: `bc25683` (`r18 repin`).
- Previous `VERSION`: `0.1.0`.
- Starting `git status --short`: empty; worktree clean before any edit.
- Most recent existing local release/tag: annotated `v0.1.0`, pointing to
  `1865fd36a05d2153425aa288dc7b17ac80c71a69`. This records the local Git baseline;
  it does not assert a Maven Central or GitHub publication.
- Confirmed upstream from `SPEC_PIN.md`: https://github.com/totipo-org/totipo-spec.
- Exact spec commit: `4623a7e1718e23504903096c92332597057bd8f0`, revision `r18`.
- Existing claims: operation-scoped protocol-foundation core and audited facade
  TOKEN projection/metadata operations; qualified low-level NIO/core store
  operations on the tested local case-sensitive Linux provider; no application
  conformance. These claims are preserved, detailed below.
- Environment: Linux, OpenJDK (Nix build) `25.0.4.1+1`, Python `3.14.7`, pinned
  Gradle `9.8.0`. The Nix-built JDK does not imply that Nix validation ran.

## Version changes

`VERSION` is the sole implementation version source. Root Gradle reads it;
subprojects and Maven publication coordinates inherit it. Publication verification
and the independent consumer also read it. No additional version source was added.
Every changed current-version reference is listed here (line numbers are baseline):

| File | Baseline references updated to 0.1.1 |
| --- | --- |
| `VERSION` | Line 1: canonical release version. |
| `README.md` | Lines 163, 168, 178, 187: proposed release prose, NIO/core consumption examples, current VERSION prose. The speculative future-patch wording is now the proposed patch. |
| `RELEASE_CHECKLIST.md` | Lines 1, 6, 13, 14, 27, 60, 127: heading, current VERSION, both Maven coordinates, proposed source-tag convention, exact core dependency mapping, future operator tag gate. |
| `publishing/consumer-smoke/gradle.lockfile` | Lines 6–7: only the two local Totipo versions. Required for strict locked consumption of 0.1.1; dependency membership/scopes and external BC remain identical. |

## Release contents

- Committed exact r18 repin and its conformance-documentation clarification.
- Documented r18 application responsibilities and API observation limitations.
- Completed CausalFact §12 metadata audit, resolving the former historical-metadata
  qualification: causal indexes are topological projections, while represented and
  captured heads preserve exact per-object metadata.
- No Java semantic implementation change from the r18 repin or audit. This release
  preparation changes version references and release documentation only.
- No new protocol feature, changed wire format, or changed portable corpus outcome.

No maintained changelog, release-history file or version table was found. The
new release-note draft is the concise 0.1.1 history entry; historical review
reports remain unchanged.

## Compatibility

No release-driven public API, wire, crypto, TOKEN, graph, fold, TOTP, or store
semantic behavior change. No production Java file changes in this worktree.
The production source diff from `v0.1.0` to starting HEAD contains comments and
Javadocs only. No public class, constructor, method, field visibility, generic
signature or method descriptor changed; dependency boundaries are unchanged.

No repository API-compatibility tool was found. For independent comparison, the
`v0.1.0` production sources were extracted outside the worktree and compiled
with the same JDK, `--release 17`, and exact BC 1.86 dependency. All **202** class
names match. `javap -public -s` output matches exactly (public declarations,
constructors, fields, descriptors and printed generics); `javap -p -c -s -constants`
also matches exactly for all production classes (instructions and declarations,
without debug source-line tables). This corroborates the documentation-only diff.

There is no `module-info.java` or `Automatic-Module-Name`; automatic module names
remain `totipo.core` and `totipo.storage.nio`. Gradle publication variants and
Java-17 requirements are unchanged apart from release version/artifact references.
The existing experimental SPI and absence of a general stability promise remain.

## Conformance

**Core:** applicable `core` protocol foundation is v1/r18 core conforming for
bootstrap reading/creation/rewrap, object crypto and identity, TOKEN
encoding/validation and exact object metadata, graph/current-state computation,
complete-value equality, bounded folds and TOTP. Audited facade TOKEN projections
and create/update/merge metadata handling, including partial resolution and frozen
publication retries, are included for these documented operations. This is
operation-scoped; every facade behavior is not certified.

**Store:** qualified `storage-nio` with low-level core observation/publication/VAULT
orchestration is v1/r18 store conforming for observation, immutable publication,
no-replace creation, replacement with exact compare-before-replace, required-byte
preservation and explicit durability results. Qualification remains the documented,
tested local case-sensitive Linux/provider capabilities. Core authenticates and
compares; the SPI does not interpret bytes. Accepted force calls and abstract tests
provide no universal filesystem/physical power-loss guarantee. Replacement is
compare-before-replace, not atomic CAS.

**Application:** no application-conformance claim. Consuming applications remain
responsible for interactive empty-password confirmation; orphan-vault warnings and
confirmation during available observation; truthful state/conflict/tombstone/
unavailable presentation; delete-versus-erasure disclosures; password-rewrap
security wording; relevant-alternative disclosure; and safe rendering of untrusted
text. Existing API limitations remain, including the absence of pre-creation orphan
context in `NioTotipo.create` and limited unavailable-object attribution in the facade.

Audit covered README, API_DESIGN, SPI_DESIGN, RELEASE_CHECKLIST, all production
package/Javadocs, POM descriptions, Gradle module definitions/metadata, and release
notes. Existing scope wording was accurate and preserved. No root-key migration/
re-key support, secure deletion, rollback protection, universal durability or
application certification is claimed.

## Test results

All four full test executions below reported **478 total tests: 363 core + 115
storage-nio, zero failures, zero errors, zero skips**. No tests were added or altered.

| Command | Result |
| --- | --- |
| `./gradlew clean test build verifyPublication consumerSmoke` | PASS: full normal clean build, publication checks and module-metadata consumer. |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test build verifyPublication consumerSmoke` | PASS: full clean forced offline build and consumer. |
| `./gradlew --no-daemon --no-build-cache --rerun-tasks clean test` | PASS: separate checklist forced normal test rerun. |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test` | PASS: separate checklist forced offline test rerun. |
| `./gradlew --offline --no-daemon --no-build-cache build verifyPublication consumerSmoke` | PASS: packages preceding clean offline outputs, publication checks and module-metadata consumer. Tests remain up-to-date; no cache restores. |
| `./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check` | PASS: independent POM-only consumer. |
| `./gradlew :core:test --tests org.totipo.conformance.SpecSnapshotIntegrityTest --tests org.totipo.conformance.R18ProfileIntegrityTest` | PASS: focused 3 snapshot + 1 profile tests; zero failures/errors/skips. |
| `git diff --check` | PASS. |

The combined clean commands execute the checklist's `clean test build` gates;
its forced normal/offline test commands also ran separately. Focused-test XML
replaces the live core report, so full accounting was copied outside `build`
before running the focused tests. The four focused tests do not replace the
478-test full-suite evidence.

`Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping` passes in
every full run, recording an ID only after semantic assertions return: **90/90**,
none deferred. Category counts: bootstrap 4, crypto 5, encoding 30, fold 6,
graph 13, metadata 7, size 1, storage 13, TOTP 3, vault 8. Portable cases are
not counted as 90 additional JUnit tests; corpus accounting is separate.

## Integrity

- `SPEC_PIN.md`, independent test pins, and every vendored snapshot file remain
  byte-identical to starting HEAD. No repin or snapshot resource modification.
- `sha256sum -c SNAPSHOT.sha256`: all 97 upstream files validate.
- `SpecSnapshotIntegrityTest`: 3/3 explicitly; independent five-artifact hashes,
  exact source commit/revision, file inventory and negative integrity checks pass.
- `R18ProfileIntegrityTest`: 1/1 explicitly; schema/manifest/spec/profile cross-pins,
  all physical case hashes and exact 90-case coverage pass.
- All 90 physical cases are byte-identical to HEAD **and** `v0.1.0`; ordered
  manifest case entries and profile `required_cases` are identical to `v0.1.0`.
  Expected outcomes are unchanged.

## Packaging

`verifyPublication` passes with exactly two staged GAVs:
`org.totipo:totipo-core:0.1.1` and `org.totipo:totipo-storage-nio:0.1.1`.
All generated POM versions, Gradle components, dependency/artifact references and
repository versions resolve to 0.1.1. Group/artifact IDs and descriptions unchanged.

Core's sole POM dependency is `org.bouncycastle:bcprov-jdk18on:1.86` at **runtime**;
NIO's sole POM dependency is `org.totipo:totipo-core:0.1.1` at **compile**. Gradle
module metadata exposes BC only in core's runtime variant and core in NIO's
API/runtime variants. Sources/Javadoc variants have no extra dependencies.
No fixture classifiers, fixture capabilities or test dependencies are published.
Both module-metadata and POM-only consumer checks compile and resolve exactly
NIO + core at compile time, adding only BC 1.86 at runtime. No source substitution,
Maven-local fallback or sibling checkout.

Binary/source/Javadoc inventories were reviewed and verified against production
class/source/generated-document directories:

| Module | Binary classes | Production Java source files | Javadoc files (excluding manifest) |
| --- | --- | --- | --- |
| core | 176 | 92 | 227 |
| storage-nio | 26 | 14 | 83 |

Every production class is non-preview Java 17 (major 61, minor 0). Binary JARs
contain exactly production classes plus manifests; source JARs contain exactly
current production sources plus manifests. Javadocs match generated current
release documents, at existing package visibility. All six manifests contain
only `Manifest-Version: 1.0`; the version is supplied by artifact names and
POM/module metadata, not a new manifest field. No test/spec resources, review
files, temporary files, credentials or signing material. POM/module metadata
contains no local filesystem paths or credentials. Structural allowlists and
checksum inventories pass.

Javadoc generation succeeds with 100 core and 90 NIO warnings (missing comments,
`@param`/`@return`/`@throws` tags and default-constructor comments). These
pre-existing documentation-completeness warnings were reviewed; no doclint error
or build failure. No release-driven Java/Javadoc source edits were made.

## Reproducibility

**10/10 artifact names and SHA-256 hashes match** across normal clean, forced
full offline, and final clean offline-output packaging builds. The latter two
use `--no-build-cache`; no cache restoration. Same environment throughout.
Inventory covers six JARs, two POMs and two `.module` files. Repository index
timestamps and detached signatures are excluded. This is same-environment
evidence, not a cross-machine guarantee.

| Artifact | SHA-256 |
| --- | --- |
| `totipo-core-0.1.1-javadoc.jar` | `1f1ace646a71158910736892ec8291cddc00e7ccf537450b5c9d6c30739a9453` |
| `totipo-core-0.1.1-sources.jar` | `fe4a2e31a1c7d6a830d0d332274603b9a82b03bd8acfda41430e436873399c83` |
| `totipo-core-0.1.1.jar` | `8a100f458fa234bb85a208537a1106eb376fed702215fc8a5d27e0bd96815c87` |
| `totipo-core-0.1.1.module` | `fbd7d4cc41e1c183a528890643e7a4a1ca7c6ca564639e262c6411bd77ea5331` |
| `totipo-core-0.1.1.pom` | `6cb13d022cceec673794497bfd092b8cb84774f30ecd3b21a3194deddbe1be66` |
| `totipo-storage-nio-0.1.1-javadoc.jar` | `0418abdf6e80bd6e03a51916a69741745660703c7f79cf0d1fd989236396dc10` |
| `totipo-storage-nio-0.1.1-sources.jar` | `038d223dc45aa6d853731da3e73bb54de88b1b3aebffb6708195ea2c3a8c0b5d` |
| `totipo-storage-nio-0.1.1.jar` | `691b56c8831f71dafb7d5cb6f7d68ee59c9f42c5bb19c29c9455e1925237334e` |
| `totipo-storage-nio-0.1.1.module` | `31344ba97aad7ade0bf2c9e37d1715b8e2ef947e0ff1bbf77be406d5a972c7fa` |
| `totipo-storage-nio-0.1.1.pom` | `09310a25382ec4adfa8f2d2f060ddb1210568c68a7feddebfefa5456242bf62a` |

## Dependency verification

Strict Gradle dependency verification passes during normal, offline and consumer
builds. No trusted-all/wildcard exceptions, new dependency, dependency refresh,
wrapper change or external dependency version change. Library locks, root plugin
lock/configuration, version catalog, verification metadata and wrapper bytes are
unchanged. Only the two local Totipo versions in the smoke lock advance, as
required for strict resolution of this release. BC remains 1.86. Root plugin
versions and dependency boundaries are unchanged, so no plugin update requiring
`buildEnvironment` review occurred. Consumer verification hashes are generated
only after structural staging verification and remain ignored build evidence.

## Nix/platform limits

`nix` is absent from PATH; documented `nix develop` validation was **not run**.
`flake.nix`, `flake.lock` and `.envrc` are unchanged. The existing checklist permits
JDK 25 + Python validation outside Nix; Nix absence alone does not block review.
No new Windows, macOS, Android, case-insensitive-provider or physical crash/
power-loss qualification. No independent interoperability/security-audit claim.

## Release notes

[Draft v0.1.1 release notes](V0_1_1_RELEASE_NOTES.md). They summarize the alignment,
compatibility, scoped claims, measured validation and limits. No release-signing
or upload evidence is asserted. Human operator must record the exact reviewed
source commit after committing and before release.

## Reference classification

All tracked files were searched at baseline for `0.1.0`, `v0.1.0`, `r17`,
`revision 17`, old r17 source SHA `1d42a481f230e0adbb89dbeaa936d3c956e70fdc`,
old r17 snapshot artifact/inventory hashes, and `next release`, `current version`,
`current target` prose. Every matching baseline line is accounted for below.
No changelog or deliberately old-version consumption example exists outside
historical reports. Final active version references are 0.1.1; remaining r17
mentions in active docs accurately describe the prior pin.

| File | Baseline matching lines | Classification/action |
| --- | --- | --- |
| `README.md` | 163, 168, 178, 186, 187 | Current version/examples updated; line 186 prior-r17 comparison retained. |
| `RELEASE_CHECKLIST.md` | 1, 6, 13, 14, 27, 60, 127 | Current/proposed release references updated; line 6 prior-r17 comparison retained. |
| `SPEC_PIN.md` | 31 | Accurate prior-pin comparison, preserved; exact r18 pin unchanged. |
| `VERSION` | 1 | Current release version references updated only. |
| `core/src/test/resources/totipo-spec/v1-pre-rc/spec/totipo-vault-format-v1.md` | 12, 816 | Exact vendored normative snapshot: authentic revision-history references; preserved byte-for-byte. |
| `publishing/consumer-smoke/gradle.lockfile` | 6, 7 | Current release version references updated only. |
| `review/J1_1_NAMESPACE_MIGRATION_REPORT.md` | 1, 12, 13, 14, 27, 28, 68, 136, 137, 138, 140, 160, 161, 170, 171, 182, 197, 202, 203, 205, 206, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 299, 300, 419, 597, 678 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/J1_MAVEN_PUBLICATION_REPORT.md` | 1, 7, 10, 12, 13, 14, 58, 59, 73, 87, 96, 97, 99, 100, 168, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 406 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/PUBLIC_API_FACADE_REPORT.md` | 21, 109, 253, 303, 405, 409, 414, 484 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/R17_IMPLEMENTATION_ADVERSARIAL_REVIEW.md` | 1, 23, 42, 48, 52, 53, 54, 56, 125, 133, 177, 214, 243, 362, 504, 544, 555, 566, 573 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/R17_IMPLEMENTATION_REMEDIATION_REPORT.md` | 1, 4, 5, 14, 31, 32, 179, 211, 297, 304, 307 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/STORAGE_SPI_REPORT.md` | 12, 279, 478 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/V1_R18_CAUSAL_FACT_METADATA_REPORT.md` | 20, 288 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |
| `review/V1_R18_REPIN_REPORT.md` | 5, 30, 50, 150, 154, 156, 157, 158, 159, 160, 164, 175, 187, 190, 200, 230, 236, 262, 264, 276, 277, 278, 291, 292, 293, 305, 313, 314, 341, 370 | Historical report: prior versions, pins, hashes and contemporaneous prose preserved. |

Old r17 artifact hashes searched: profile `ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e`;
spec `f8d2ab02c97e8ac54847048a06cb088359db982fec3f176fd473ce0f223d43cf`;
FORMAT `0ddaf84ff214a0859abd29f1f104792854940f25ec87f5dc849ca3b3d84d8a74`;
manifest `94fff22842573e15b254bb0653970761c15cf122192947a36fccc48344a84f08`;
manifest schema `e7a5d8ec0392e0248ab867375b7c907a7ca1298595acdb14ecd3edcbe66df476`;
SNAPSHOT inventory `08e9e85f7b3ae048913136b83c33e6cdaf3ebc0b898a906420f4ec64ed26a526`.
Matches are historical evidence in prior reports, preserved. The case schema
hash remains valid at r18; it is intentionally unchanged.

## Files changed

| File | Reason |
| --- | --- |
| `VERSION` | Canonical patch version 0.1.1. |
| `README.md` | Current release/consumer examples and links to new release evidence; scoped claims preserved. |
| `RELEASE_CHECKLIST.md` | Proposed 0.1.1 version/coordinates/operator tag gates, preserving release safeguards. |
| `publishing/consumer-smoke/gradle.lockfile` | Required update of two local Totipo versions only. |
| `review/V0_1_1_RELEASE_NOTES.md` (added) | Concise proposed patch notes/history entry. |
| `review/V0_1_1_RELEASE_PREPARATION_REPORT.md` (added) | This measured preparation/validation report. |

No deleted file. No generated output tracked or evidence added from `/tmp`.
Temporary logs, XML, API inventories and hash copies stayed outside the worktree;
ignored build outputs remain local. All changed content was reviewed for
credentials/signing material and unintended release or semantic changes.

## `git diff --stat`

Tracked diff (Git does not include the two untracked new reports in this output):

```text
 README.md                                 | 15 +++++++++------
 RELEASE_CHECKLIST.md                      | 16 ++++++++--------
 VERSION                                   |  2 +-
 publishing/consumer-smoke/gradle.lockfile |  4 ++--
 4 files changed, 20 insertions(+), 17 deletions(-)
```

## `git status --short`

```text
 M README.md
 M RELEASE_CHECKLIST.md
 M VERSION
 M publishing/consumer-smoke/gradle.lockfile
?? review/V0_1_1_RELEASE_NOTES.md
?? review/V0_1_1_RELEASE_PREPARATION_REPORT.md
```

## Release readiness

Suitable for human commit/tag/release review as proposed v0.1.1, subject to the
existing human operator gates. Exact r18 pin and corpus unchanged; 90/90 pass;
478 tests pass; Java 17, package consumers, metadata/inventories and reproducible
artifacts pass. No semantic production change, blanket facade claim or application
conformance claim. Nix validation and wider platform/power-loss qualification
remain unavailable/unperformed as stated.

The checklist's clean starting-worktree gate was met. Its final reviewed commit
record/tag and Central/post-release gates are intentionally pending human review;
this uncommitted worktree is not an actual released source commit. No Git staging,
commit, tag `v0.1.1`, signing, external publishing/upload, GitHub release or push
was performed. Local unsigned Maven staging is validation only.
