# J1.1 namespace migration review — 0.1.0

## Baseline, authority and scope

The initial working tree was clean at committed J1:
`e84767fb141cc37e4bd06ff15b19378642d4f563` (`prepare for release to maven central`).
Before any repository edit, `./gradlew clean test build verifyPublication consumerSmoke`
passed. Baseline: **346 core tests, 115 storage-nio tests, zero failures/errors/skips,
90/90 portable cases, all 202 production classfiles Java 17 (major 61, minor 0)**.
The baseline log and inventories are temporary evidence under `/tmp/totipo-j11-*`.

`VERSION` remains byte-identical: `0.1.0` plus final LF, the sole publication version
source. Protocol target remains **Totipo Vault Format v1/r17**, pinned to exact
specification commit `1d42a481f230e0adbb89dbeaa936d3c956e70fdc`.
Snapshot timestamp remains `2026-09-29T22:48:30Z`; no pin or snapshot hash changed.

The operator reports ownership of `totipo.org`; the GitHub organization is now
`totipo-org`. Java and Maven identity are aligned with that domain before the first
public release. Central namespace verification has **not** been performed or
claimed. The release checklist retains the operator's namespace-authority gate.
This report supersedes J1's coordinates for release readiness; committed historical
review reports, including `J1_MAVEN_PUBLICATION_REPORT.md`, are byte-identical.

| Identity | Before | After |
| --- | --- | --- |
| Java package prefix | `dev.totipo.*` | `org.totipo.*` |
| Core Maven GAV | `dev.totipo:totipo-core:0.1.0` | `org.totipo:totipo-core:0.1.0` |
| NIO Maven GAV | `dev.totipo:totipo-storage-nio:0.1.0` | `org.totipo:totipo-storage-nio:0.1.0` |
| Java repository | `https://github.com/totipo-dev/totipo-java` | `https://github.com/totipo-org/totipo-java` |
| Specification repository | `https://github.com/totipo-dev/totipo-spec` | `https://github.com/totipo-org/totipo-spec` |

No current desktop repository URL needed changing. No sibling desktop or spec
repository was edited. No artifact ID, simple class name, implementation version,
protocol revision, compatibility shim, relocation POM or umbrella artifact was added
or changed. No new dependency, API compatibility plugin or JPMS setup was introduced.

## Searches and migration inventory

Before editing, all four requested broad searches were run and retained under `/tmp`:
`rg -n 'dev\.totipo'`, `rg -n 'dev/totipo'`, `rg -n 'totipo-dev'`, and
`rg -n 'github\.com/totipo-dev'`. A hidden-file search additionally covered CI.
All hits were classified as Java declarations/imports/FQCNs, Java API documentation
(including one package-info comment), source links, Maven group/path/configuration,
consumer locks, repository URL/SCM metadata, or historical review evidence.
There were no namespace hits in protocol or test resources.

Directories were moved with `git mv`, preserving structure below `totipo`:

| Source root | Files moved from `java/dev/totipo` to `java/org/totipo` |
| --- | ---: |
| `core/src/main` | 92 |
| `core/src/test` | 43 |
| `storage-nio/src/main` | 14 |
| `storage-nio/src/test` | 9 |
| `storage-nio/src/testFixtures` | 3 |

Core production sources now comprise 36 files in `org.totipo`, 43 in
`org.totipo.format`, and 13 in `org.totipo.spi` (including package-info).
All 14 NIO production sources remain in `org.totipo.storage.nio`.
No package was reorganized. The standalone, default-package `ConsumerSmoke.java`
keeps its path and changes only imports. Fully qualified references in
`ApplicationSession`, `ApplicationVaults`, `NioDiscoverySource`, `NioVaultStorage`,
`TokenStoreReaderTest` and `ApplicationCausalFixture` identify Java types and were
migrated with their declarations.

Current README, API_DESIGN, SPI_DESIGN, RELEASE_CHECKLIST, shared publication
configuration, verifier, consumer settings/build/lock and imports are updated.
README still says 0.1.0 is being prepared and does not claim Central availability.
CI invokes the same updated verification tasks and contains no coordinate or source
path to change. The flake likewise contains no namespace-sensitive reference;
both CI and flake remain byte-identical, with no secrets or release workflow added.

### Services, reflection, serialization and module identity

- `find . -path '*/META-INF/services/*' -print` found no service descriptors.
  There is no `ServiceLoader` use and no service-discovery behavior to migrate.
- No `Class.forName`, class-name reflection lookup, method handles or production
  class-name resource lookup exists. The test reflection in `TokenPublicationTest`
  inspects declared field types using class literals; its semantics are unchanged.
  `VectorCaseLoader.class.getResourceAsStream` uses the absolute, unchanged
  `/totipo-spec/v1-pre-rc/vectors/` resource prefix, independent of its Java package.
- The unusual serialization hits are six `serialVersionUID = 1L` declarations:
  `SessionClosedException`, `ByteCursor.TruncatedInput`, `StoreAdapter.DefiniteFailure`,
  `NioObjectStorage.Different`, `NioNamespace`, and `NioNamespace.Collision`.
  These inherit exception serialization capability; the public exception is not
  claimed to be non-serializable. There is no production native-serialization
  persistence path, declared serialization contract, `ObjectInputStream`,
  `ObjectOutputStream`, `Externalizable`, `writeReplace`, or `readResolve`, and no
  persistence of FQCNs. SPI `readObject` means bounded protocol-object bytes, not
  Java deserialization. No compatibility workaround was added.
- No `Automatic-Module-Name`, `module-info.java`, package-valued manifest field or
  service resource exists. Both binary manifests contain only `Manifest-Version: 1.0`.

## Mechanical source and compiled API audits

`/tmp/totipo-j11-source-audit.py` reads every baseline Java file directly from
`git show HEAD:<old-path>`, maps only `/dev/totipo/` to `/org/totipo/` in the path,
and compares the new file's bytes against old bytes with only `dev.totipo` replaced
by `org.totipo`. **All 106 production files match exactly**, without even whitespace
changes beyond the substitution. All 55 test/helper/fixture files and the consumer
source pass the same check. The complete Java file set matches the mapped baseline;
no Java file or test was added or removed.

Inspection of the production diff confirms that all changed lines are package
prefixes, imports, qualified Java type references, or the SPI package-info Java API
comment. No algorithms, control flow, constants, crypto, TLV encoding, object IDs,
storage behavior, state/observation, token or password semantics changed.

Before renaming, JDK `javap -protected -s` was run on every compiled production
`.class`, including nested classes, with paths sorted per module. It captures class
and interface declarations, constructors, methods, fields, generic signatures and
JVM descriptors. The inventory includes non-public classes as a stronger superset
of the requested public surface. The same script regenerated the inventory afterward.
Normalizing only dotted and slash-separated package prefixes in the baseline yields
**byte-identical API inventories**. This covers 102 public declarations in core and
7 in NIO, as well as the additional non-public declarations.

The independent, sorted production class-path inventories also match exactly after
`dev/totipo` -> `org/totipo`: **176 core classes and 26 NIO classes**. No class was
added or removed. All classfiles have magic `CAFEBABE`, minor 0, major 61. JDK 25
builds with the existing Java 17 production target; no separate Java 17 runtime
execution qualification is asserted.

Temporary evidence (not committed source):
`/tmp/totipo-j11-inventory.py`, `/tmp/totipo-j11-before/{core,storage-nio}-{api,classes}.txt`,
and the equivalent `/tmp/totipo-j11-after/` files.

## Specification, durable format and portable corpus

`git diff HEAD -- SPEC_PIN.md` contains exactly one URL substitution, changing the
canonical upstream repository to `totipo-org/totipo-spec`. Every other byte remains
unchanged. Authoritative hash values retained:

| Pinned artifact | SHA-256 |
| --- | --- |
| `spec/totipo-vault-format-v1.md` | `f8d2ab02c97e8ac54847048a06cb088359db982fec3f176fd473ce0f223d43cf` |
| `vectors/manifest.json` | `94fff22842573e15b254bb0653970761c15cf122192947a36fccc48344a84f08` |
| `vectors/manifest.schema.json` | `e7a5d8ec0392e0248ab867375b7c907a7ca1298595acdb14ecd3edcbe66df476` |
| `vectors/case.schema.json` | `d38618f53dcf0a558c389831e8838a07248066beff392812f3d277cc974e25c9` |
| `requirements/v1-pre-rc.json` | `ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e` |

All **98 committed resource files** (97 imported upstream files plus `SNAPSHOT.sha256`)
under `core/src/test/resources/totipo-spec/v1-pre-rc/` match J1 byte-for-byte.
The resource-tree Git diff is empty. No vector, JSON, expected outcome or checksum
was regenerated. Neither old nor new dotted/slash Java namespace occurs in these
resources. Together with exact source equivalence and the absence of native object
serialization or persisted class names, this establishes that this migration has
not changed the language-independent wire or durable representation.

Final tests: **346 core, 115 storage-nio; zero failures, errors or skips**.
`Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping` passes and still
executes all **90/90** portable cases before accounting for them: bootstrap 4,
crypto 5, encoding 30, fold 6, graph 13, metadata 7, size 1, storage 13, TOTP 3,
vault 8. None are deferred. Snapshot/profile integrity tests also pass.

## Publication boundary and consumer

After clean staging, `build/repository` contains exactly these two GAV directories:

- `org/totipo/totipo-core/0.1.0`
- `org/totipo/totipo-storage-nio/0.1.0`

There is no `dev/totipo` staging tree, relocation publication, extra artifact or
signature. The verifier confirms the complete unsigned repository inventory and
checksums: binary/source/Javadoc JARs, POM and module metadata for each GAV, plus
checksum sidecars and the expected repository indexes (60 files total).

| Publication | Only POM dependency | Scope |
| --- | --- | --- |
| `org.totipo:totipo-core:0.1.0` | `org.bouncycastle:bcprov-jdk18on:1.86` | runtime |
| `org.totipo:totipo-storage-nio:0.1.0` | `org.totipo:totipo-core:0.1.0` | compile |

Structural XML validation verifies project URL and SCM URL
`https://github.com/totipo-org/totipo-java`, connection
`scm:git:https://github.com/totipo-org/totipo-java.git`, and developer connection
`scm:git:ssh://git@github.com/totipo-org/totipo-java.git`. Existing license/developer
metadata is unchanged. No test/fixture/optional/classifier dependency is present;
BC is still an implementation/runtime dependency, absent from core's compile API.

Structural Gradle `.module` validation confirms the exact new GAVs and the same four
variants: `apiElements`, `runtimeElements`, `sourcesElements`, `javadocElements`.
Both NIO production variants require exact `org.totipo:totipo-core:0.1.0`;
core API has no dependency and core runtime requires BC 1.86. Production variants
retain JVM target 17. No old group, project path, fixture variant/capability,
unexpected classifier or dynamic dependency version is present.

J1's negative coordinate tests were temporary probes documented in its report,
not committed test files. They were repeated with new coordinates using
`/tmp/totipo-j11-negative.py`. With valid sidecar checksums recomputed for each
mutation, the verifier rejects wrong core artifact names in both POM and module
metadata. Additional probes reject the old group, dynamic versions, project-path
leakage, fixture variants/capabilities, test dependencies and unexpected classifiers.
Each mutation is restored in a `finally` block; the original publication verifies
again afterward. No validation rule was weakened.

The standalone consumer's only requested Totipo dependency remains
`org.totipo:totipo-storage-nio:0.1.0`, with the version read from `VERSION`.
Both Gradle metadata and offline POM-only modes compile and pass exact graph checks:

```text
compileClasspath
└── org.totipo:totipo-storage-nio:0.1.0
    └── org.totipo:totipo-core:0.1.0
runtimeClasspath
└── org.totipo:totipo-storage-nio:0.1.0
    └── org.totipo:totipo-core:0.1.0
        └── org.bouncycastle:bcprov-jdk18on:1.86
```

Resolution rejects project components. There is no `includeBuild`, source
substitution, project dependency, sibling checkout lookup or Maven-local fallback.
The exclusive file repository permits only `org.totipo`; Maven Central remains
restricted to the BC module. No repository trust was broadened.

## Locks, verification, CI and signing

Root dependency verification metadata, settings/core/storage locks, and the
consumer's external BC verification template are byte-identical to J1. Consumer
locks were updated and confirmed by offline `--write-locks`; their only content delta is
the two Totipo group prefixes, with Gradle restoring alphabetical ordering around BC. The verifier regenerates the ignored local consumer
verification file from inspected artifacts using the existing J1 mechanism.
No unrelated version, checksum, repository or dependency churn was accepted.

Vanniktech remains pinned to 0.37.0. `-PcentralRelease=true` still enables signing
and manual `publishToMavenCentral`, with `automaticRelease=false`. Credential names
and signing mechanics are unchanged. The signing dry run includes both modules'
`signMavenPublication` tasks for the new publication coordinates; no task executes,
no real secret is supplied, and no signature is produced. Actual signing, namespace
verification, Portal validation and publication remain human release gates.

**No Maven Central upload, namespace registration/verification, deployment/state
change, signing, tag, release or commit occurred.** No operator credential was used.
All work remains uncommitted in this Java repository. Directory moves are staged
by `git mv`; their namespace-content edits and operational changes remain unstaged.

## Reproducibility and new release hashes

Two clean uncached publication builds (second offline) generated the same ten
unsigned release files. The first manifest was copied outside `build` to
`/tmp/totipo-j11-repro-first.json`; `cmp` against the second
`build/publication-sha256.json` returned 0. These are the new namespace's baseline,
not comparisons against old J1 hashes. Repository-index timestamps and signatures
are excluded as in J1. This proves repeatability within this environment.

| File (beneath its GAV directory) | SHA-256 (both builds) |
| --- | --- |
| `totipo-core-0.1.0-javadoc.jar` | `815705140dd6a8ff99ca2ab16895cab242e38304f73a7b08b3975abf344194d2` |
| `totipo-core-0.1.0-sources.jar` | `f859001841c7cbca1ed1e6526634eeaad52cd32b907048e4e4d5d1abdd078476` |
| `totipo-core-0.1.0.jar` | `cdc34b76c39895d421b6c0e1fa416193541b88c758aae4d2dcaee881e5c5ca13` |
| `totipo-core-0.1.0.module` | `6f10a916b57108db1205213f464ef855a74a13cb09dc70b590bea69dd23c937b` |
| `totipo-core-0.1.0.pom` | `35b0b0fa56fb3b4d5e9372bfcb203a64ee31119554e2803a366f6036b26710bd` |
| `totipo-storage-nio-0.1.0-javadoc.jar` | `0a9252932aecef1bc7db38c5b9c50f818b840277cd2f38dcc02f7c4c85291e4e` |
| `totipo-storage-nio-0.1.0-sources.jar` | `945ebe28f29e458fdb8b44f6ae4f180b91f0772d38b559595d9cbc70af090a3b` |
| `totipo-storage-nio-0.1.0.jar` | `8c55ef0ecf67c88e47d0d283dc4312f273100cd956e326c53b355e46e889ef3e` |
| `totipo-storage-nio-0.1.0.module` | `abfd1100942b97c97c3d9a0d48d24d0d5655a44befed5cf3068829c671cc194f` |
| `totipo-storage-nio-0.1.0.pom` | `cee7b49124b54182c68595de0bfc88b80c21d8a3b31f7adf13c9dd0dbf12ebaf` |

## Validation commands

All commands passed without credentials. Gradle 9.8.0 and Nix OpenJDK
25.0.4.1+1 were used; Python 3.14.7 supplied the standard-library verifier.
Existing missing-Javadoc-comment warnings remain; Javadoc generation succeeds.
No build or audit failure required a production change.

| Command | Result |
| --- | --- |
| `./gradlew clean test build verifyPublication consumerSmoke` (before edits) | PASS; clean J1 baseline |
| `./gradlew clean test build` | PASS |
| `./gradlew --no-daemon --no-build-cache --rerun-tasks clean test` | PASS |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test` | PASS |
| `./gradlew verifyPublication consumerSmoke` | PASS |
| `./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check` | PASS; also repeated after final staging |
| `./gradlew -p publishing/consumer-smoke --offline --write-locks clean check` | PASS; reviewed group-only lock change and generated ordering |
| `python3 /tmp/totipo-j11-negative.py` | PASS; malformed publications rejected, originals restored |
| `./gradlew --no-daemon --no-build-cache --rerun-tasks clean test verifyPublication` | PASS; first release hash baseline |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test verifyPublication consumerSmoke` | PASS; second release hash baseline |
| `cmp /tmp/totipo-j11-repro-first.json build/publication-sha256.json` | PASS; all ten files identical |
| `./gradlew -PcentralRelease=true :core:signMavenPublication :storage-nio:signMavenPublication --dry-run` | PASS; both signing tasks skipped as expected in dry run |
| `python3 /tmp/totipo-j11-source-audit.py` | PASS; exact Java equivalence, resources/pin/locks/historical evidence |
| `python3 /tmp/totipo-j11-inventory.py after` and normalized inventory comparison | PASS; API, class sets, Java 17 and test counts |
| `git diff --check` and `git diff --cached --check` | PASS |

## Final identity audit and historical exceptions

The four old-identity searches were repeated, including hidden current files.
There are no old namespace/organization hits outside `review/` in current tracked
source, tests, builds, CI, operational documentation/scripts, consumer configuration
or publication verification. Generated Maven POMs, module metadata, indexes and the
consumer verification file also contain no old identity. Reverse searches for
`org.totipo`, `org/totipo` and `totipo-org` confirm Java APIs/packages, source links,
Maven groups/staging paths and canonical repository/SCM URLs in their correct roles.
No namespace string was added to protocol resources.

Every remaining pre-existing old-identity hit is historical, in these unchanged
reports (line numbers in J1 and the working tree):

- `review/J1_MAVEN_PUBLICATION_REPORT.md` (70 matching lines): 58–59, 66, 73, 87, 96–97, 99–100, 187–246, 295.
- `review/PUBLIC_API_FACADE_REPORT.md` (4 matching lines): 43, 88, 92, 238.
- `review/R17_IMPLEMENTATION_ADVERSARIAL_REVIEW.md` (6 matching lines): 62, 200–203, 424.
- `review/R17_IMPLEMENTATION_REMEDIATION_REPORT.md` (20 matching lines): 233–252.
- `review/STORAGE_SPI_REPORT.md` (13 matching lines): 35, 56–57, 350–359.

These 113 historical matching lines describe former Java APIs, source paths,
coordinates, staged artifacts or GitHub URLs and intentionally retain their original
meaning. This new report additionally mentions the former identity in explicit
before/after comparisons, audit methodology and Git evidence; those are migration
evidence, not current consumption or release instructions.

## Final worktree evidence

The following snapshots are taken after creating this report. The report is
untracked and therefore excluded from the tracked-file diff statistic. `git mv`
accounts for the staged path moves; `RM` means the content edit is additionally
unstaged. No commit was created.

`git status --short`:

```text
 M API_DESIGN.md
 M README.md
 M RELEASE_CHECKLIST.md
 M SPEC_PIN.md
 M SPI_DESIGN.md
 M build.gradle.kts
RM core/src/main/java/dev/totipo/ClientMetadata.java -> core/src/main/java/org/totipo/ClientMetadata.java
RM core/src/main/java/dev/totipo/CompetingField.java -> core/src/main/java/org/totipo/CompetingField.java
RM core/src/main/java/dev/totipo/CompetingSecret.java -> core/src/main/java/org/totipo/CompetingSecret.java
RM core/src/main/java/dev/totipo/CreateToken.java -> core/src/main/java/org/totipo/CreateToken.java
RM core/src/main/java/dev/totipo/CreateVaultResult.java -> core/src/main/java/org/totipo/CreateVaultResult.java
RM core/src/main/java/dev/totipo/MergeSecretChoice.java -> core/src/main/java/org/totipo/MergeSecretChoice.java
RM core/src/main/java/dev/totipo/MergeToken.java -> core/src/main/java/org/totipo/MergeToken.java
RM core/src/main/java/dev/totipo/NewSecret.java -> core/src/main/java/org/totipo/NewSecret.java
RM core/src/main/java/dev/totipo/ObservationProgress.java -> core/src/main/java/org/totipo/ObservationProgress.java
RM core/src/main/java/dev/totipo/OpenResult.java -> core/src/main/java/org/totipo/OpenResult.java
RM core/src/main/java/dev/totipo/PartialResolution.java -> core/src/main/java/org/totipo/PartialResolution.java
RM core/src/main/java/dev/totipo/PartialSaveResult.java -> core/src/main/java/org/totipo/PartialSaveResult.java
RM core/src/main/java/dev/totipo/PasswordChangeResult.java -> core/src/main/java/org/totipo/PasswordChangeResult.java
RM core/src/main/java/dev/totipo/PublicationRetry.java -> core/src/main/java/org/totipo/PublicationRetry.java
RM core/src/main/java/dev/totipo/RetryResult.java -> core/src/main/java/org/totipo/RetryResult.java
RM core/src/main/java/dev/totipo/RevisionId.java -> core/src/main/java/org/totipo/RevisionId.java
RM core/src/main/java/dev/totipo/SaveResult.java -> core/src/main/java/org/totipo/SaveResult.java
RM core/src/main/java/dev/totipo/SecretGroup.java -> core/src/main/java/org/totipo/SecretGroup.java
RM core/src/main/java/dev/totipo/SessionClosedException.java -> core/src/main/java/org/totipo/SessionClosedException.java
RM core/src/main/java/dev/totipo/TokenAlternative.java -> core/src/main/java/org/totipo/TokenAlternative.java
RM core/src/main/java/dev/totipo/TokenCompetition.java -> core/src/main/java/org/totipo/TokenCompetition.java
RM core/src/main/java/dev/totipo/TokenDescriptor.java -> core/src/main/java/org/totipo/TokenDescriptor.java
RM core/src/main/java/dev/totipo/TokenEditor.java -> core/src/main/java/org/totipo/TokenEditor.java
RM core/src/main/java/dev/totipo/TokenHead.java -> core/src/main/java/org/totipo/TokenHead.java
RM core/src/main/java/dev/totipo/TokenId.java -> core/src/main/java/org/totipo/TokenId.java
RM core/src/main/java/dev/totipo/TokenState.java -> core/src/main/java/org/totipo/TokenState.java
RM core/src/main/java/dev/totipo/TokenStatus.java -> core/src/main/java/org/totipo/TokenStatus.java
RM core/src/main/java/dev/totipo/Totipo.java -> core/src/main/java/org/totipo/Totipo.java
RM core/src/main/java/dev/totipo/TotpAlgorithm.java -> core/src/main/java/org/totipo/TotpAlgorithm.java
RM core/src/main/java/dev/totipo/TotpCode.java -> core/src/main/java/org/totipo/TotpCode.java
RM core/src/main/java/dev/totipo/UnresolvedReference.java -> core/src/main/java/org/totipo/UnresolvedReference.java
RM core/src/main/java/dev/totipo/UpdateToken.java -> core/src/main/java/org/totipo/UpdateToken.java
RM core/src/main/java/dev/totipo/VaultDiagnostic.java -> core/src/main/java/org/totipo/VaultDiagnostic.java
RM core/src/main/java/dev/totipo/VaultFingerprint.java -> core/src/main/java/org/totipo/VaultFingerprint.java
RM core/src/main/java/dev/totipo/VaultSession.java -> core/src/main/java/org/totipo/VaultSession.java
RM core/src/main/java/dev/totipo/VaultState.java -> core/src/main/java/org/totipo/VaultState.java
RM core/src/main/java/dev/totipo/format/ApplicationSession.java -> core/src/main/java/org/totipo/format/ApplicationSession.java
RM core/src/main/java/dev/totipo/format/ApplicationStates.java -> core/src/main/java/org/totipo/format/ApplicationStates.java
RM core/src/main/java/dev/totipo/format/ApplicationVaults.java -> core/src/main/java/org/totipo/format/ApplicationVaults.java
RM core/src/main/java/dev/totipo/format/Argon2idKdf.java -> core/src/main/java/org/totipo/format/Argon2idKdf.java
RM core/src/main/java/dev/totipo/format/BouncyCastleArgon2idKdf.java -> core/src/main/java/org/totipo/format/BouncyCastleArgon2idKdf.java
RM core/src/main/java/dev/totipo/format/BoundedObjectRead.java -> core/src/main/java/org/totipo/format/BoundedObjectRead.java
RM core/src/main/java/dev/totipo/format/ByteCursor.java -> core/src/main/java/org/totipo/format/ByteCursor.java
RM core/src/main/java/dev/totipo/format/CryptoSupport.java -> core/src/main/java/org/totipo/format/CryptoSupport.java
RM core/src/main/java/dev/totipo/format/DiscoverySource.java -> core/src/main/java/org/totipo/format/DiscoverySource.java
RM core/src/main/java/dev/totipo/format/EntropySource.java -> core/src/main/java/org/totipo/format/EntropySource.java
RM core/src/main/java/dev/totipo/format/EnvelopeReader.java -> core/src/main/java/org/totipo/format/EnvelopeReader.java
RM core/src/main/java/dev/totipo/format/ObjectId.java -> core/src/main/java/org/totipo/format/ObjectId.java
RM core/src/main/java/dev/totipo/format/PasswordBytes.java -> core/src/main/java/org/totipo/format/PasswordBytes.java
RM core/src/main/java/dev/totipo/format/SecurityBytes.java -> core/src/main/java/org/totipo/format/SecurityBytes.java
RM core/src/main/java/dev/totipo/format/StoreAdapter.java -> core/src/main/java/org/totipo/format/StoreAdapter.java
RM core/src/main/java/dev/totipo/format/StrictUtf8.java -> core/src/main/java/org/totipo/format/StrictUtf8.java
RM core/src/main/java/dev/totipo/format/TlvField.java -> core/src/main/java/org/totipo/format/TlvField.java
RM core/src/main/java/dev/totipo/format/TlvReader.java -> core/src/main/java/org/totipo/format/TlvReader.java
RM core/src/main/java/dev/totipo/format/TlvWriter.java -> core/src/main/java/org/totipo/format/TlvWriter.java
RM core/src/main/java/dev/totipo/format/TokenFold.java -> core/src/main/java/org/totipo/format/TokenFold.java
RM core/src/main/java/dev/totipo/format/TokenGraph.java -> core/src/main/java/org/totipo/format/TokenGraph.java
RM core/src/main/java/dev/totipo/format/TokenId.java -> core/src/main/java/org/totipo/format/TokenId.java
RM core/src/main/java/dev/totipo/format/TokenMetadata.java -> core/src/main/java/org/totipo/format/TokenMetadata.java
RM core/src/main/java/dev/totipo/format/TokenObject.java -> core/src/main/java/org/totipo/format/TokenObject.java
RM core/src/main/java/dev/totipo/format/TokenPublicationPlan.java -> core/src/main/java/org/totipo/format/TokenPublicationPlan.java
RM core/src/main/java/dev/totipo/format/TokenPublisher.java -> core/src/main/java/org/totipo/format/TokenPublisher.java
RM core/src/main/java/dev/totipo/format/TokenReader.java -> core/src/main/java/org/totipo/format/TokenReader.java
RM core/src/main/java/dev/totipo/format/TokenStoreObservation.java -> core/src/main/java/org/totipo/format/TokenStoreObservation.java
RM core/src/main/java/dev/totipo/format/TokenStoreReader.java -> core/src/main/java/org/totipo/format/TokenStoreReader.java
RM core/src/main/java/dev/totipo/format/TokenValue.java -> core/src/main/java/org/totipo/format/TokenValue.java
RM core/src/main/java/dev/totipo/format/TokenWriter.java -> core/src/main/java/org/totipo/format/TokenWriter.java
RM core/src/main/java/dev/totipo/format/Totp.java -> core/src/main/java/org/totipo/format/Totp.java
RM core/src/main/java/dev/totipo/format/UInt64.java -> core/src/main/java/org/totipo/format/UInt64.java
RM core/src/main/java/dev/totipo/format/V1EnvelopeWriter.java -> core/src/main/java/org/totipo/format/V1EnvelopeWriter.java
RM core/src/main/java/dev/totipo/format/V1ObjectPublicationStore.java -> core/src/main/java/org/totipo/format/V1ObjectPublicationStore.java
RM core/src/main/java/dev/totipo/format/ValidatedToken.java -> core/src/main/java/org/totipo/format/ValidatedToken.java
RM core/src/main/java/dev/totipo/format/VaultBootstrap.java -> core/src/main/java/org/totipo/format/VaultBootstrap.java
RM core/src/main/java/dev/totipo/format/VaultBootstrapReplacementStorage.java -> core/src/main/java/org/totipo/format/VaultBootstrapReplacementStorage.java
RM core/src/main/java/dev/totipo/format/VaultBootstrapStorage.java -> core/src/main/java/org/totipo/format/VaultBootstrapStorage.java
RM core/src/main/java/dev/totipo/format/VaultBootstrapWriter.java -> core/src/main/java/org/totipo/format/VaultBootstrapWriter.java
RM core/src/main/java/dev/totipo/format/VaultLifecycle.java -> core/src/main/java/org/totipo/format/VaultLifecycle.java
RM core/src/main/java/dev/totipo/format/VaultUnlockResult.java -> core/src/main/java/org/totipo/format/VaultUnlockResult.java
RM core/src/main/java/dev/totipo/format/VaultUnlocker.java -> core/src/main/java/org/totipo/format/VaultUnlocker.java
RM core/src/main/java/dev/totipo/spi/BoundedRead.java -> core/src/main/java/org/totipo/spi/BoundedRead.java
RM core/src/main/java/dev/totipo/spi/EntryKind.java -> core/src/main/java/org/totipo/spi/EntryKind.java
RM core/src/main/java/dev/totipo/spi/ObjectEntry.java -> core/src/main/java/org/totipo/spi/ObjectEntry.java
RM core/src/main/java/dev/totipo/spi/ObjectName.java -> core/src/main/java/org/totipo/spi/ObjectName.java
RM core/src/main/java/dev/totipo/spi/ObjectScan.java -> core/src/main/java/org/totipo/spi/ObjectScan.java
RM core/src/main/java/dev/totipo/spi/ObjectWrite.java -> core/src/main/java/org/totipo/spi/ObjectWrite.java
RM core/src/main/java/dev/totipo/spi/PreparedVault.java -> core/src/main/java/org/totipo/spi/PreparedVault.java
RM core/src/main/java/dev/totipo/spi/StoreFailure.java -> core/src/main/java/org/totipo/spi/StoreFailure.java
RM core/src/main/java/dev/totipo/spi/TotipoStore.java -> core/src/main/java/org/totipo/spi/TotipoStore.java
RM core/src/main/java/dev/totipo/spi/VaultInstall.java -> core/src/main/java/org/totipo/spi/VaultInstall.java
RM core/src/main/java/dev/totipo/spi/VaultPrepare.java -> core/src/main/java/org/totipo/spi/VaultPrepare.java
RM core/src/main/java/dev/totipo/spi/VaultReplace.java -> core/src/main/java/org/totipo/spi/VaultReplace.java
RM core/src/main/java/dev/totipo/spi/package-info.java -> core/src/main/java/org/totipo/spi/package-info.java
RM core/src/test/java/dev/totipo/api/PublicApiTest.java -> core/src/test/java/org/totipo/api/PublicApiTest.java
RM core/src/test/java/dev/totipo/api/SpiApplicationTest.java -> core/src/test/java/org/totipo/api/SpiApplicationTest.java
RM core/src/test/java/dev/totipo/conformance/R17ProfileIntegrityTest.java -> core/src/test/java/org/totipo/conformance/R17ProfileIntegrityTest.java
RM core/src/test/java/dev/totipo/conformance/SpecSnapshotIntegrityTest.java -> core/src/test/java/org/totipo/conformance/SpecSnapshotIntegrityTest.java
RM core/src/test/java/dev/totipo/conformance/VectorCaseLoader.java -> core/src/test/java/org/totipo/conformance/VectorCaseLoader.java
RM core/src/test/java/dev/totipo/conformance/VectorCaseLoaderTest.java -> core/src/test/java/org/totipo/conformance/VectorCaseLoaderTest.java
RM core/src/test/java/dev/totipo/format/ApplicationCausalFixture.java -> core/src/test/java/org/totipo/format/ApplicationCausalFixture.java
RM core/src/test/java/dev/totipo/format/BootstrapVectorTest.java -> core/src/test/java/org/totipo/format/BootstrapVectorTest.java
RM core/src/test/java/dev/totipo/format/ByteCursorTest.java -> core/src/test/java/org/totipo/format/ByteCursorTest.java
RM core/src/test/java/dev/totipo/format/CryptoSupportTest.java -> core/src/test/java/org/totipo/format/CryptoSupportTest.java
RM core/src/test/java/dev/totipo/format/DiscoverySourceTest.java -> core/src/test/java/org/totipo/format/DiscoverySourceTest.java
RM core/src/test/java/dev/totipo/format/EnvelopeReaderTest.java -> core/src/test/java/org/totipo/format/EnvelopeReaderTest.java
RM core/src/test/java/dev/totipo/format/EnvelopeTestBytes.java -> core/src/test/java/org/totipo/format/EnvelopeTestBytes.java
RM core/src/test/java/dev/totipo/format/FakeV1ObjectPublicationStore.java -> core/src/test/java/org/totipo/format/FakeV1ObjectPublicationStore.java
RM core/src/test/java/dev/totipo/format/GraphFoldVectorChecks.java -> core/src/test/java/org/totipo/format/GraphFoldVectorChecks.java
RM core/src/test/java/dev/totipo/format/GraphFoldVectorTest.java -> core/src/test/java/org/totipo/format/GraphFoldVectorTest.java
RM core/src/test/java/dev/totipo/format/PasswordBytesTest.java -> core/src/test/java/org/totipo/format/PasswordBytesTest.java
RM core/src/test/java/dev/totipo/format/Phase2ConformanceTest.java -> core/src/test/java/org/totipo/format/Phase2ConformanceTest.java
RM core/src/test/java/dev/totipo/format/PublicationTestStore.java -> core/src/test/java/org/totipo/format/PublicationTestStore.java
RM core/src/test/java/dev/totipo/format/SecurityBytesTest.java -> core/src/test/java/org/totipo/format/SecurityBytesTest.java
RM core/src/test/java/dev/totipo/format/StorageVectorChecks.java -> core/src/test/java/org/totipo/format/StorageVectorChecks.java
RM core/src/test/java/dev/totipo/format/StorageVectorTest.java -> core/src/test/java/org/totipo/format/StorageVectorTest.java
RM core/src/test/java/dev/totipo/format/TlvReaderTest.java -> core/src/test/java/org/totipo/format/TlvReaderTest.java
RM core/src/test/java/dev/totipo/format/TlvTestBytes.java -> core/src/test/java/org/totipo/format/TlvTestBytes.java
RM core/src/test/java/dev/totipo/format/TokenCodecTest.java -> core/src/test/java/org/totipo/format/TokenCodecTest.java
RM core/src/test/java/dev/totipo/format/TokenFoldTest.java -> core/src/test/java/org/totipo/format/TokenFoldTest.java
RM core/src/test/java/dev/totipo/format/TokenGraphTest.java -> core/src/test/java/org/totipo/format/TokenGraphTest.java
RM core/src/test/java/dev/totipo/format/TokenNioWorkflowTest.java -> core/src/test/java/org/totipo/format/TokenNioWorkflowTest.java
RM core/src/test/java/dev/totipo/format/TokenPublicationTest.java -> core/src/test/java/org/totipo/format/TokenPublicationTest.java
RM core/src/test/java/dev/totipo/format/TokenStoreReaderTest.java -> core/src/test/java/org/totipo/format/TokenStoreReaderTest.java
RM core/src/test/java/dev/totipo/format/TokenVectorChecks.java -> core/src/test/java/org/totipo/format/TokenVectorChecks.java
RM core/src/test/java/dev/totipo/format/TotpTest.java -> core/src/test/java/org/totipo/format/TotpTest.java
RM core/src/test/java/dev/totipo/format/TotpVectorTest.java -> core/src/test/java/org/totipo/format/TotpVectorTest.java
RM core/src/test/java/dev/totipo/format/V1ObjectPublicationStoreTest.java -> core/src/test/java/org/totipo/format/V1ObjectPublicationStoreTest.java
RM core/src/test/java/dev/totipo/format/VaultBootstrapTest.java -> core/src/test/java/org/totipo/format/VaultBootstrapTest.java
RM core/src/test/java/dev/totipo/format/VaultBootstrapWriterTest.java -> core/src/test/java/org/totipo/format/VaultBootstrapWriterTest.java
RM core/src/test/java/dev/totipo/format/VaultLifecycleTest.java -> core/src/test/java/org/totipo/format/VaultLifecycleTest.java
RM core/src/test/java/dev/totipo/format/VaultNioWorkflowTest.java -> core/src/test/java/org/totipo/format/VaultNioWorkflowTest.java
RM core/src/test/java/dev/totipo/format/VaultTestStore.java -> core/src/test/java/org/totipo/format/VaultTestStore.java
RM core/src/test/java/dev/totipo/format/VaultUnlockerTest.java -> core/src/test/java/org/totipo/format/VaultUnlockerTest.java
RM core/src/test/java/dev/totipo/format/VaultVectorChecks.java -> core/src/test/java/org/totipo/format/VaultVectorChecks.java
RM core/src/test/java/dev/totipo/format/VaultVectorTest.java -> core/src/test/java/org/totipo/format/VaultVectorTest.java
RM core/src/test/java/dev/totipo/testing/MemoryVault.java -> core/src/test/java/org/totipo/testing/MemoryVault.java
 M publishing/consumer-smoke/build.gradle.kts
 M publishing/consumer-smoke/gradle.lockfile
 M publishing/consumer-smoke/settings.gradle.kts
 M publishing/consumer-smoke/src/main/java/ConsumerSmoke.java
 M publishing/verify-publication.py
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioApplicationPublication.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioApplicationPublication.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioDiscoverySource.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioDiscoverySource.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioDurability.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioDurability.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioFiles.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioFiles.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioNamespace.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioNamespace.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioObjectScan.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioObjectScan.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioObjectStorage.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioObjectStorage.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioReads.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioReads.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioTotipo.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioTotipo.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioTotipoStore.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioTotipoStore.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioV1ObjectPublicationStore.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioV1ObjectPublicationStore.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioVaultBootstrapStorage.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioVaultBootstrapStorage.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/NioVaultStorage.java -> storage-nio/src/main/java/org/totipo/storage/nio/NioVaultStorage.java
RM storage-nio/src/main/java/dev/totipo/storage/nio/StorageDurability.java -> storage-nio/src/main/java/org/totipo/storage/nio/StorageDurability.java
RM storage-nio/src/test/java/dev/totipo/format/NioDiscoveryTest.java -> storage-nio/src/test/java/org/totipo/format/NioDiscoveryTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/DurabilityContractTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/DurabilityContractTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/NioApplicationPublicationTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/NioApplicationPublicationTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/NioDurabilityTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/NioDurabilityTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/NioExactNameTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/NioExactNameTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/NioPublicationTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/NioPublicationTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/NioSpiTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/NioSpiTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/NioVaultStorageTest.java -> storage-nio/src/test/java/org/totipo/storage/nio/NioVaultStorageTest.java
RM storage-nio/src/test/java/dev/totipo/storage/nio/RecordingDurability.java -> storage-nio/src/test/java/org/totipo/storage/nio/RecordingDurability.java
RM storage-nio/src/testFixtures/java/dev/totipo/storage/nio/ObjectPublicationFaults.java -> storage-nio/src/testFixtures/java/org/totipo/storage/nio/ObjectPublicationFaults.java
RM storage-nio/src/testFixtures/java/dev/totipo/storage/nio/ReplacementStorageFaults.java -> storage-nio/src/testFixtures/java/org/totipo/storage/nio/ReplacementStorageFaults.java
RM storage-nio/src/testFixtures/java/dev/totipo/storage/nio/VaultStorageFaults.java -> storage-nio/src/testFixtures/java/org/totipo/storage/nio/VaultStorageFaults.java
?? review/J1_1_NAMESPACE_MIGRATION_REPORT.md
```

`git diff --stat` (unstaged content changes):

```text
 API_DESIGN.md                                      |  6 ++--
 README.md                                          | 14 +++++----
 RELEASE_CHECKLIST.md                               | 13 +++++---
 SPEC_PIN.md                                        |  2 +-
 SPI_DESIGN.md                                      | 10 +++---
 build.gradle.kts                                   | 12 ++++----
 core/src/main/java/org/totipo/ClientMetadata.java  |  2 +-
 core/src/main/java/org/totipo/CompetingField.java  |  2 +-
 core/src/main/java/org/totipo/CompetingSecret.java |  2 +-
 core/src/main/java/org/totipo/CreateToken.java     |  2 +-
 .../main/java/org/totipo/CreateVaultResult.java    |  2 +-
 .../main/java/org/totipo/MergeSecretChoice.java    |  2 +-
 core/src/main/java/org/totipo/MergeToken.java      |  2 +-
 core/src/main/java/org/totipo/NewSecret.java       |  2 +-
 .../main/java/org/totipo/ObservationProgress.java  |  2 +-
 core/src/main/java/org/totipo/OpenResult.java      |  2 +-
 .../main/java/org/totipo/PartialResolution.java    |  2 +-
 .../main/java/org/totipo/PartialSaveResult.java    |  2 +-
 .../main/java/org/totipo/PasswordChangeResult.java |  2 +-
 .../src/main/java/org/totipo/PublicationRetry.java |  2 +-
 core/src/main/java/org/totipo/RetryResult.java     |  2 +-
 core/src/main/java/org/totipo/RevisionId.java      |  2 +-
 core/src/main/java/org/totipo/SaveResult.java      |  2 +-
 core/src/main/java/org/totipo/SecretGroup.java     |  2 +-
 .../java/org/totipo/SessionClosedException.java    |  2 +-
 .../src/main/java/org/totipo/TokenAlternative.java |  2 +-
 .../src/main/java/org/totipo/TokenCompetition.java |  2 +-
 core/src/main/java/org/totipo/TokenDescriptor.java |  2 +-
 core/src/main/java/org/totipo/TokenEditor.java     |  2 +-
 core/src/main/java/org/totipo/TokenHead.java       |  2 +-
 core/src/main/java/org/totipo/TokenId.java         |  2 +-
 core/src/main/java/org/totipo/TokenState.java      |  2 +-
 core/src/main/java/org/totipo/TokenStatus.java     |  2 +-
 core/src/main/java/org/totipo/Totipo.java          |  6 ++--
 core/src/main/java/org/totipo/TotpAlgorithm.java   |  2 +-
 core/src/main/java/org/totipo/TotpCode.java        |  2 +-
 .../main/java/org/totipo/UnresolvedReference.java  |  2 +-
 core/src/main/java/org/totipo/UpdateToken.java     |  2 +-
 core/src/main/java/org/totipo/VaultDiagnostic.java |  2 +-
 .../src/main/java/org/totipo/VaultFingerprint.java |  2 +-
 core/src/main/java/org/totipo/VaultSession.java    |  2 +-
 core/src/main/java/org/totipo/VaultState.java      |  2 +-
 .../java/org/totipo/format/ApplicationSession.java | 36 +++++++++++-----------
 .../java/org/totipo/format/ApplicationStates.java  |  4 +--
 .../java/org/totipo/format/ApplicationVaults.java  |  8 ++---
 .../main/java/org/totipo/format/Argon2idKdf.java   |  2 +-
 .../org/totipo/format/BouncyCastleArgon2idKdf.java |  2 +-
 .../java/org/totipo/format/BoundedObjectRead.java  |  2 +-
 .../main/java/org/totipo/format/ByteCursor.java    |  2 +-
 .../main/java/org/totipo/format/CryptoSupport.java |  2 +-
 .../java/org/totipo/format/DiscoverySource.java    |  2 +-
 .../main/java/org/totipo/format/EntropySource.java |  2 +-
 .../java/org/totipo/format/EnvelopeReader.java     |  2 +-
 core/src/main/java/org/totipo/format/ObjectId.java |  2 +-
 .../main/java/org/totipo/format/PasswordBytes.java |  2 +-
 .../main/java/org/totipo/format/SecurityBytes.java |  2 +-
 .../main/java/org/totipo/format/StoreAdapter.java  |  4 +--
 .../main/java/org/totipo/format/StrictUtf8.java    |  2 +-
 core/src/main/java/org/totipo/format/TlvField.java |  2 +-
 .../src/main/java/org/totipo/format/TlvReader.java |  2 +-
 .../src/main/java/org/totipo/format/TlvWriter.java |  2 +-
 .../src/main/java/org/totipo/format/TokenFold.java |  2 +-
 .../main/java/org/totipo/format/TokenGraph.java    |  2 +-
 core/src/main/java/org/totipo/format/TokenId.java  |  2 +-
 .../main/java/org/totipo/format/TokenMetadata.java |  2 +-
 .../main/java/org/totipo/format/TokenObject.java   |  2 +-
 .../org/totipo/format/TokenPublicationPlan.java    |  2 +-
 .../java/org/totipo/format/TokenPublisher.java     |  2 +-
 .../main/java/org/totipo/format/TokenReader.java   |  2 +-
 .../org/totipo/format/TokenStoreObservation.java   |  2 +-
 .../java/org/totipo/format/TokenStoreReader.java   |  2 +-
 .../main/java/org/totipo/format/TokenValue.java    |  2 +-
 .../main/java/org/totipo/format/TokenWriter.java   |  2 +-
 core/src/main/java/org/totipo/format/Totp.java     |  2 +-
 core/src/main/java/org/totipo/format/UInt64.java   |  2 +-
 .../java/org/totipo/format/V1EnvelopeWriter.java   |  2 +-
 .../totipo/format/V1ObjectPublicationStore.java    |  2 +-
 .../java/org/totipo/format/ValidatedToken.java     |  2 +-
 .../java/org/totipo/format/VaultBootstrap.java     |  2 +-
 .../format/VaultBootstrapReplacementStorage.java   |  2 +-
 .../org/totipo/format/VaultBootstrapStorage.java   |  2 +-
 .../org/totipo/format/VaultBootstrapWriter.java    |  2 +-
 .../java/org/totipo/format/VaultLifecycle.java     |  2 +-
 .../java/org/totipo/format/VaultUnlockResult.java  |  2 +-
 .../main/java/org/totipo/format/VaultUnlocker.java |  2 +-
 core/src/main/java/org/totipo/spi/BoundedRead.java |  2 +-
 core/src/main/java/org/totipo/spi/EntryKind.java   |  2 +-
 core/src/main/java/org/totipo/spi/ObjectEntry.java |  2 +-
 core/src/main/java/org/totipo/spi/ObjectName.java  |  2 +-
 core/src/main/java/org/totipo/spi/ObjectScan.java  |  2 +-
 core/src/main/java/org/totipo/spi/ObjectWrite.java |  2 +-
 .../main/java/org/totipo/spi/PreparedVault.java    |  2 +-
 .../src/main/java/org/totipo/spi/StoreFailure.java |  2 +-
 core/src/main/java/org/totipo/spi/TotipoStore.java |  2 +-
 .../src/main/java/org/totipo/spi/VaultInstall.java |  2 +-
 .../src/main/java/org/totipo/spi/VaultPrepare.java |  2 +-
 .../src/main/java/org/totipo/spi/VaultReplace.java |  2 +-
 .../src/main/java/org/totipo/spi/package-info.java |  4 +--
 .../test/java/org/totipo/api/PublicApiTest.java    | 10 +++---
 .../java/org/totipo/api/SpiApplicationTest.java    |  8 ++---
 .../conformance/R17ProfileIntegrityTest.java       |  2 +-
 .../conformance/SpecSnapshotIntegrityTest.java     |  2 +-
 .../org/totipo/conformance/VectorCaseLoader.java   |  2 +-
 .../totipo/conformance/VectorCaseLoaderTest.java   |  2 +-
 .../totipo/format/ApplicationCausalFixture.java    | 10 +++---
 .../org/totipo/format/BootstrapVectorTest.java     |  6 ++--
 .../java/org/totipo/format/ByteCursorTest.java     |  2 +-
 .../java/org/totipo/format/CryptoSupportTest.java  |  2 +-
 .../org/totipo/format/DiscoverySourceTest.java     |  2 +-
 .../java/org/totipo/format/EnvelopeReaderTest.java |  4 +--
 .../java/org/totipo/format/EnvelopeTestBytes.java  |  4 +--
 .../format/FakeV1ObjectPublicationStore.java       |  2 +-
 .../org/totipo/format/GraphFoldVectorChecks.java   |  6 ++--
 .../org/totipo/format/GraphFoldVectorTest.java     |  4 +--
 .../java/org/totipo/format/PasswordBytesTest.java  |  2 +-
 .../org/totipo/format/Phase2ConformanceTest.java   |  4 +--
 .../org/totipo/format/PublicationTestStore.java    |  2 +-
 .../java/org/totipo/format/SecurityBytesTest.java  |  2 +-
 .../org/totipo/format/StorageVectorChecks.java     | 12 ++++----
 .../java/org/totipo/format/StorageVectorTest.java  |  4 +--
 .../test/java/org/totipo/format/TlvReaderTest.java |  4 +--
 .../test/java/org/totipo/format/TlvTestBytes.java  |  2 +-
 .../java/org/totipo/format/TokenCodecTest.java     |  2 +-
 .../test/java/org/totipo/format/TokenFoldTest.java |  4 +--
 .../java/org/totipo/format/TokenGraphTest.java     |  2 +-
 .../org/totipo/format/TokenNioWorkflowTest.java    | 12 ++++----
 .../org/totipo/format/TokenPublicationTest.java    |  4 +--
 .../org/totipo/format/TokenStoreReaderTest.java    |  4 +--
 .../java/org/totipo/format/TokenVectorChecks.java  |  6 ++--
 core/src/test/java/org/totipo/format/TotpTest.java |  2 +-
 .../java/org/totipo/format/TotpVectorTest.java     |  8 ++---
 .../format/V1ObjectPublicationStoreTest.java       |  2 +-
 .../java/org/totipo/format/VaultBootstrapTest.java |  4 +--
 .../totipo/format/VaultBootstrapWriterTest.java    |  2 +-
 .../java/org/totipo/format/VaultLifecycleTest.java |  6 ++--
 .../org/totipo/format/VaultNioWorkflowTest.java    | 18 +++++------
 .../java/org/totipo/format/VaultTestStore.java     |  2 +-
 .../java/org/totipo/format/VaultUnlockerTest.java  |  4 +--
 .../java/org/totipo/format/VaultVectorChecks.java  |  6 ++--
 .../java/org/totipo/format/VaultVectorTest.java    |  4 +--
 .../test/java/org/totipo/testing/MemoryVault.java  |  6 ++--
 publishing/consumer-smoke/build.gradle.kts         |  4 +--
 publishing/consumer-smoke/gradle.lockfile          |  4 +--
 publishing/consumer-smoke/settings.gradle.kts      |  2 +-
 .../src/main/java/ConsumerSmoke.java               |  8 ++---
 publishing/verify-publication.py                   | 18 +++++------
 .../storage/nio/NioApplicationPublication.java     |  6 ++--
 .../org/totipo/storage/nio/NioDiscoverySource.java | 12 ++++----
 .../java/org/totipo/storage/nio/NioDurability.java |  2 +-
 .../main/java/org/totipo/storage/nio/NioFiles.java |  2 +-
 .../java/org/totipo/storage/nio/NioNamespace.java  |  4 +--
 .../java/org/totipo/storage/nio/NioObjectScan.java |  4 +--
 .../org/totipo/storage/nio/NioObjectStorage.java   |  2 +-
 .../main/java/org/totipo/storage/nio/NioReads.java |  4 +--
 .../java/org/totipo/storage/nio/NioTotipo.java     |  8 ++---
 .../org/totipo/storage/nio/NioTotipoStore.java     |  4 +--
 .../storage/nio/NioV1ObjectPublicationStore.java   |  6 ++--
 .../storage/nio/NioVaultBootstrapStorage.java      |  4 +--
 .../org/totipo/storage/nio/NioVaultStorage.java    |  4 +--
 .../org/totipo/storage/nio/StorageDurability.java  |  2 +-
 .../java/org/totipo/format/NioDiscoveryTest.java   |  4 +--
 .../totipo/storage/nio/DurabilityContractTest.java |  6 ++--
 .../storage/nio/NioApplicationPublicationTest.java |  6 ++--
 .../org/totipo/storage/nio/NioDurabilityTest.java  |  2 +-
 .../org/totipo/storage/nio/NioExactNameTest.java   |  6 ++--
 .../org/totipo/storage/nio/NioPublicationTest.java |  6 ++--
 .../java/org/totipo/storage/nio/NioSpiTest.java    |  4 +--
 .../totipo/storage/nio/NioVaultStorageTest.java    |  2 +-
 .../totipo/storage/nio/RecordingDurability.java    |  2 +-
 .../storage/nio/ObjectPublicationFaults.java       |  2 +-
 .../storage/nio/ReplacementStorageFaults.java      |  2 +-
 .../org/totipo/storage/nio/VaultStorageFaults.java |  2 +-
 172 files changed, 319 insertions(+), 314 deletions(-)
```

`git diff HEAD --stat` aggregate (including staged directory moves):

```text
 172 files changed, 319 insertions(+), 314 deletions(-)
```

Ready for operator review and org.totipo Maven Central 0.1.0 publication
