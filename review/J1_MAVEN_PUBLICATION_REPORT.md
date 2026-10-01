# J1 Maven publication review — 0.1.0

## Baseline and scope

The initial `git status --short` was empty. Baseline Java commit:
`2d64f75859923b4c07787c17d0eee6863470ac09`.
`VERSION` now contains exactly `0.1.0` plus LF. All published versions derive
from this file; protocol revision and implementation version remain independent.
The release source commit is intentionally pending operator review/commit and
must be recorded with tag `v0.1.0`; no tag or commit was made by this pass.

The unchanged `SPEC_PIN.md` identifies Totipo Vault Format v1/r17 at
`1d42a481f230e0adbb89dbeaa936d3c956e70fdc`. Its profile SHA-256 is
`ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e`.
The complete suite retains 90/90 executed portable cases: bootstrap 4, crypto 5,
encoding 30, fold 6, graph 13, metadata 7, size 1, storage 13, TOTP 3, vault 8.
`Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping` executes each
case before accounting for it and asserts that total/category inventory.
Snapshot integrity tests independently validate the pin and file hashes.

No production Java sources, public contracts, cryptography, wire encoding,
protocol/state/storage semantics, corpus data/outcomes, spec snapshot or SPEC_PIN
were changed. No `totipo-desktop` files were inspected or modified.

## Publishing integration and compatibility

Exactly pinned `com.vanniktech.maven.publish:0.37.0` is the current stable upstream
release (GitHub latest-release API: non-prerelease, 2026-06-21), selected after
reading the current [Central documentation](https://vanniktech.github.io/gradle-maven-publish-plugin/central/),
[changelog](https://vanniktech.github.io/gradle-maven-publish-plugin/changelog/),
and [0.37.0 source](https://github.com/vanniktech/gradle-maven-publish-plugin/tree/0.37.0).
Upstream minimums are Gradle 9.0/JDK 17, with testing through Gradle 9.6.0,
9.7.0-milestone-1 and JDK 26. This pass separately validates Gradle **9.8.0**
on the repository's Nix-provided **OpenJDK 25.0.4.1+1**, targeting Java 17.
It does not claim upstream tested Gradle 9.8.0.

[opvaultj's build](https://github.com/ingon/opvaultj/blob/main/build.gradle) uses
0.34.0, the same coordinates/POM/Central/signing model, and developer identity
`ingon`, Nikolay Petrov, `https://github.com/ingon/`. That existing identity is
retained; no organization or contributor was invented. Differences: current
plugin version; Totipo coordinates/Apache license; a shared VERSION; two modules;
explicit opt-in Central configuration; unsigned local staging; and use of the
already-defined Java component source/Javadoc archives. Plugin archive creation
is disabled via `JavaLibrary(JavadocJar.None(), SourcesJar.None())` because the
Java component already supplies the real source/Javadoc variants. Nothing is
empty or omitted from the resulting publications.

An initial staging attempt exposed duplicate Javadoc output tasks between plugin
defaults and existing `withJavadocJar()`. Explicit component configuration fixed
that task dependency conflict and also prevents fixture-source creation. No
additional publishing plugin was added; Vanniktech uses Gradle's built-in Maven
publishing/signing facilities.

## Coordinates, POM and Gradle metadata

| Publication | Exact dependency in generated POM | Scope |
| --- | --- | --- |
| `dev.totipo:totipo-core:0.1.0` | `org.bouncycastle:bcprov-jdk18on:1.86` | runtime |
| `dev.totipo:totipo-storage-nio:0.1.0` | `dev.totipo:totipo-core:0.1.0` | compile |

There are no other POM dependencies. The root has no publication, BOM or umbrella
artifact. Archive names still match artifact IDs; project/package names did not
change. BC remains an unshaded external implementation dependency.

Both POMs structurally validate names (`Totipo Java Core`, `Totipo Java NIO
Storage`), module descriptions, project URL `https://github.com/totipo-dev/totipo-java`,
Apache License 2.0 and its official license URL, the developer above, HTTPS SCM
connection and SSH developer connection to that same repository.

Each `.module` declares its correct GAV and exactly `apiElements`,
`runtimeElements`, `sourcesElements`, `javadocElements`. Core API has no dependency;
its runtime has BC 1.86. NIO API and runtime both require exact
`dev.totipo:totipo-core:0.1.0`. Production variants declare JVM 17. No project
paths, fixture variants/capabilities, test dependencies or extra classifiers are
published. `verifyPublication` parses XML and JSON, rather than matching POM text,
and fails on incorrect coordinate rewriting or dependency scope/variant drift.

`storage-nio` still applies `java-test-fixtures`; internal core tests consume it.
The Java component explicitly skips fixture API/runtime publication variants.
Source publication uses only the existing main source set, so no fixture sources
variant is created. Complete tests continue exercising internal fixture usage.

## Binary consumer boundary

`publishing/consumer-smoke` is a committed, standalone Gradle project, not included
in the root settings. Its single requested dependency is
`dev.totipo:totipo-storage-nio:0.1.0` (version read from VERSION). It compiles calls
using `NioTotipo`, `OpenResult`, `VaultSession`, `VaultState` and the state publisher.
No real vault is needed, no SPI/internal class is used, and no source/composite
substitution is configured. Resolution assertions reject project components.

Both Gradle module metadata and `-PpomOnly` consumer modes pass. The exact graph:

```text
compileClasspath
└── dev.totipo:totipo-storage-nio:0.1.0
    └── dev.totipo:totipo-core:0.1.0
runtimeClasspath
└── dev.totipo:totipo-storage-nio:0.1.0
    └── dev.totipo:totipo-core:0.1.0
        └── org.bouncycastle:bcprov-jdk18on:1.86
```

There is no Jackson, JUnit, test fixture or spec resource dependency. Totipo is
exclusive to the generated file repository; Central is allowed only for BC.
No Maven-local fallback, includeBuild, sibling discovery, vendored source or
project substitution is used. The primary test does not touch `~/.m2/repository`.

The consumer has strict locks and verification. Its committed template pins BC's
existing JAR/POM hashes. After validating staged contents and metadata, the verifier
generates exact checksums for locally built Totipo JAR/POM/module files into an
ignored consumer verification file. This checks the current staged artifacts
without pinning CI to one vendor's JDK output; it introduces no trusted artifact,
key or wildcard exception. Re-run root `verifyPublication` before standalone use.

## Dependency and supply-chain review

Normal dependency repositories remain Maven Central; Plugin Portal is confined
to plugin management. Existing core/storage/settings lockfiles are byte-identical
to baseline. Production runtime inventory before/after remains BC 1.86 plus NIO's
core dependency. Jackson 2.18.2 and JUnit 6.1.3 remain test-only. Library locking
is explicitly STRICT; verification is explicitly strict with metadata enabled.
Buildscript/plugin resolution is separate from library lockfiles; the exact
plugin pin and verification hashes protect that classpath, not runtime locks.

Generated verification delta: **36 artifact SHA-256 entries across 21 components**;
all **32 existing artifact entries unchanged**. Reviewed against `buildEnvironment`:
Vanniktech's Portal client accounts for the HTTP/JSON/logging dependencies; Gradle's
embedded Kotlin constraints select 2.4.10. Okio 3.7.0 is metadata consulted during
conflict resolution to 3.15.0, not a second runtime JAR. SLF4J parent/BOM are
metadata-only. Every added file was independently re-fetched from Maven Central
(or the Plugin Portal for the marker) and hashed, with all 36 matches. This is
checksum/origin and graph review, not a claim of a separate signature audit.
No unrelated dependency, repository relaxation or broad verification exception
was introduced. Exact additions follow (full SHA-256 values are committed in
`gradle/verification-metadata.xml`).

| Component | Added verified artifacts |
| --- | --- |
| `com.squareup.moshi:moshi:1.15.2` | `moshi-1.15.2.jar`, `moshi-1.15.2.module` |
| `com.squareup.moshi:moshi-kotlin:1.15.2` | `moshi-kotlin-1.15.2.jar`, `moshi-kotlin-1.15.2.module` |
| `com.squareup.okhttp3:okhttp:5.1.0` | `okhttp-5.1.0.module` |
| `com.squareup.okhttp3:okhttp-jvm:5.1.0` | `okhttp-jvm-5.1.0.jar`, `okhttp-jvm-5.1.0.module` |
| `com.squareup.okio:okio:3.15.0` | `okio-3.15.0.module` |
| `com.squareup.okio:okio:3.7.0` | `okio-3.7.0.module` |
| `com.squareup.okio:okio-jvm:3.15.0` | `okio-jvm-3.15.0.jar`, `okio-jvm-3.15.0.module` |
| `com.squareup.retrofit2:converter-moshi:3.0.0` | `converter-moshi-3.0.0.jar`, `converter-moshi-3.0.0.module` |
| `com.squareup.retrofit2:converter-scalars:3.0.0` | `converter-scalars-3.0.0.jar`, `converter-scalars-3.0.0.module` |
| `com.squareup.retrofit2:retrofit:3.0.0` | `retrofit-3.0.0.jar`, `retrofit-3.0.0.module` |
| `com.vanniktech:central-portal:0.37.0` | `central-portal-0.37.0.jar`, `central-portal-0.37.0.module` |
| `com.vanniktech:gradle-maven-publish-plugin:0.37.0` | `gradle-maven-publish-plugin-0.37.0.jar`, `gradle-maven-publish-plugin-0.37.0.module` |
| `com.vanniktech.maven.publish:com.vanniktech.maven.publish.gradle.plugin:0.37.0` | `com.vanniktech.maven.publish.gradle.plugin-0.37.0.pom` |
| `org.jetbrains:annotations:13.0` | `annotations-13.0.jar`, `annotations-13.0.pom` |
| `org.jetbrains.kotlin:kotlin-reflect:2.4.10` | `kotlin-reflect-2.4.10.jar`, `kotlin-reflect-2.4.10.pom` |
| `org.jetbrains.kotlin:kotlin-stdlib:2.4.10` | `kotlin-stdlib-2.4.10.jar`, `kotlin-stdlib-2.4.10.module` |
| `org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.8.21` | `kotlin-stdlib-jdk7-1.8.21.jar`, `kotlin-stdlib-jdk7-1.8.21.pom` |
| `org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.8.21` | `kotlin-stdlib-jdk8-1.8.21.jar`, `kotlin-stdlib-jdk8-1.8.21.pom` |
| `org.slf4j:slf4j-api:2.0.18` | `slf4j-api-2.0.18.jar`, `slf4j-api-2.0.18.pom` |
| `org.slf4j:slf4j-bom:2.0.18` | `slf4j-bom-2.0.18.pom` |
| `org.slf4j:slf4j-parent:2.0.18` | `slf4j-parent-2.0.18.pom` |

## Staged files and archive contents

`build/repository` has exactly two artifact/version directories. Each has binary,
source and Javadoc JARs, a POM and a `.module`, plus MD5/SHA-1/SHA-256/SHA-512
sidecars for each (25 files per GAV). Each artifact directory also has Gradle's
`maven-metadata.xml` index and its four sidecars (5 files). Total: **60 files**.
The index only lists 0.1.0. All sidecar checksums were verified. No signatures
are expected in this deliberately unsigned staging path; arbitrary extra files
(including `.asc` here), classifiers or a third artifact fail verification.

| Module | Binary contents | Source contents | Javadoc contents |
| --- | --- | --- | --- |
| core | 176 production classes + manifest | 92 production Java sources + manifest | 227 generated documentation/assets + manifest |
| storage-nio | 26 production classes + manifest | 14 production Java sources + manifest | 83 generated documentation/assets + manifest |

Every binary entry is matched to production compilation output and checked for
classfile magic, non-preview minor version 0 and major version **61**. Source
entries are matched byte-for-byte to main sources. Javadoc entries match generated
documentation, including index.html. Existing package-level Javadoc visibility
is unchanged. Existing missing-comment warnings occur (100-warning cap per
module); generation succeeds. No test/fixture classes, Jackson, JUnit, embedded
BC, spec snapshots, vector JSON, source/build files in binary JARs or review docs
appear. Full final inventory relative to `build/repository`:

```text
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-javadoc.jar
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-javadoc.jar.md5
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-javadoc.jar.sha1
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-javadoc.jar.sha256
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-javadoc.jar.sha512
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-sources.jar
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-sources.jar.md5
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-sources.jar.sha1
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-sources.jar.sha256
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0-sources.jar.sha512
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.jar
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.jar.md5
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.jar.sha1
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.jar.sha256
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.jar.sha512
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.module
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.module.md5
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.module.sha1
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.module.sha256
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.module.sha512
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.pom
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.pom.md5
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.pom.sha1
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.pom.sha256
dev/totipo/totipo-core/0.1.0/totipo-core-0.1.0.pom.sha512
dev/totipo/totipo-core/maven-metadata.xml
dev/totipo/totipo-core/maven-metadata.xml.md5
dev/totipo/totipo-core/maven-metadata.xml.sha1
dev/totipo/totipo-core/maven-metadata.xml.sha256
dev/totipo/totipo-core/maven-metadata.xml.sha512
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-javadoc.jar
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-javadoc.jar.md5
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-javadoc.jar.sha1
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-javadoc.jar.sha256
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-javadoc.jar.sha512
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-sources.jar
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-sources.jar.md5
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-sources.jar.sha1
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-sources.jar.sha256
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0-sources.jar.sha512
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.jar
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.jar.md5
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.jar.sha1
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.jar.sha256
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.jar.sha512
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.module
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.module.md5
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.module.sha1
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.module.sha256
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.module.sha512
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.pom
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.pom.md5
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.pom.sha1
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.pom.sha256
dev/totipo/totipo-storage-nio/0.1.0/totipo-storage-nio-0.1.0.pom.sha512
dev/totipo/totipo-storage-nio/maven-metadata.xml
dev/totipo/totipo-storage-nio/maven-metadata.xml.md5
dev/totipo/totipo-storage-nio/maven-metadata.xml.sha1
dev/totipo/totipo-storage-nio/maven-metadata.xml.sha256
dev/totipo/totipo-storage-nio/maven-metadata.xml.sha512
```

## Reproducibility

All archive tasks use reproducible file order and discard timestamps. Two clean
builds with `--no-build-cache --rerun-tasks` (second offline) produced identical
SHA-256 for **all ten** release files. The comparison used the verifier-generated
`build/publication-sha256.json`, saved as `/tmp/j1-repro-first.json` before the
second clean, then `cmp` (exit 0). Generated Javadoc omits timestamps. Gradle
repository indexes contain changing update times and are excluded; signatures
were not generated and are not expected to be reproducible. This establishes
same-environment repeatability only, not cross-machine reproducibility.

| File | SHA-256 (both builds) |
| --- | --- |
| `totipo-core-0.1.0-javadoc.jar` | `925d659a606557f73d68c06f65591b53f211292abb902fcfa4e7c2a3002fdaa5` |
| `totipo-core-0.1.0-sources.jar` | `21c8d4a0c2de1ee4a901580703de5ef10ce7bc176510527feb3743a47983e9ff` |
| `totipo-core-0.1.0.jar` | `7347d1e9647ed687d258b94d2a4c9dfe3e759f30a0642d86811cf05f2affa836` |
| `totipo-core-0.1.0.module` | `4039df3edde85913575f8dae10b9edf80455a3aa7a768786231290470ccb942d` |
| `totipo-core-0.1.0.pom` | `05758520ad7a4e6b4803b913ab82780cc732d081446d3993e5dcbe006ee7fcb0` |
| `totipo-storage-nio-0.1.0-javadoc.jar` | `8745dc7a275f1fed922b6a04c85281b9c9c851f9ce3eec37d2959cda2bb3187a` |
| `totipo-storage-nio-0.1.0-sources.jar` | `cec725a5eebf26c2960ba0cf322cb3caf3203bed3fab90e64c10062d995d2839` |
| `totipo-storage-nio-0.1.0.jar` | `52f41e691db0b7a445e1d8995cd8f3733b15ac8e92c060c28ba82218e7a6b81b` |
| `totipo-storage-nio-0.1.0.module` | `ea9b167e062d2bdb2f6667685a0be3bea97f121968fdcf4b9f4c24b8840c7a47` |
| `totipo-storage-nio-0.1.0.pom` | `a6561e1f505cad28d90590de0e60b6635cff05cc0a2800e508724ff491778e98` |

## Central and signing

`-PcentralRelease=true` jointly enables the current Central Portal and
`signAllPublications()`, with `automaticRelease=false`. Without that flag only
unsigned local staging is configured; ordinary `build`, `check`, `test`, archives,
Javadocs, POMs, publication verification and consumer smoke need no secrets.
Generic `publish` with the release flag fails with an explicit-task instruction.
There are no legacy OSSRH endpoints or additional public release repositories.

A signing-task dry run covered both modules, with no upload task invoked. A
read-only Gradle initialization audit realized each publication's artifacts,
asserted `SigningExtension.required`, and inspected `signMavenPublication`'s
signature inputs: binary JAR, source JAR, Javadoc JAR, `pom-default.xml`,
`module.json` for each module. All five are required. The initial audit looked
at a lazy artifact collection before realizing it and saw only POM/module;
after realizing the publication it confirmed all five, without changing config.
This is static configuration evidence, not actual cryptographic signing.

Operator secrets: `mavenCentralUsername`, `mavenCentralPassword` (Portal token
fields), `signingInMemoryKey`, optional `signingInMemoryKeyId`, and
`signingInMemoryKeyPassword`. Gradle environment property prefix:
`ORG_GRADLE_PROJECT_`. No credential was read, printed or checked in.
The operator must establish authority for `dev.totipo`, supply credentials and
key externally, inspect `.asc` signatures, upload with the explicit manual
procedure, check Portal validation, and release after review. The checklist also
documents the distinct automatic publish-and-release task; it was not selected.

**No Maven Central upload, deployment creation/closing/release, snapshot upload,
namespace mutation, GitHub package publication, commit or tag occurred.** Actual
signing, Central validation and independent Central download remain human gates.
Release source commit must be recorded after review. Desktop may migrate only
when both artifacts are independently downloadable from Central.

## Validation commands and results

Commands run from the repository root; JDK 25 was already on PATH. Python 3.13.13
was available in the Nix store but absent from the initial shell PATH, so for
publication commands its bin directory was prepended to PATH and `--no-daemon`
used to ensure a fresh daemon inherited it. `flake.nix` now includes Python in
both development and agent shells. No third-party Python package is used.

| Command/check | Result |
| --- | --- |
| `git status --short`; `git rev-parse HEAD` before editing | Clean; baseline SHA above |
| `./gradlew clean test build` before editing | PASS, full baseline build, 2m28s |
| `./gradlew --write-verification-metadata sha256 help` | Generated only plugin graph additions; reviewed/re-fetched as above |
| `./gradlew buildEnvironment` | PASS; plugin/transitive inventory reviewed |
| `./gradlew --no-daemon clean test build verifyPublication consumerSmoke` | PASS, ordinary credential-free build and binary consumer |
| `./gradlew --no-daemon --no-build-cache --rerun-tasks clean test verifyPublication` | PASS, 29 tasks executed, 1m39s; first clean artifact hash set |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test verifyPublication consumerSmoke` | PASS, 30 tasks executed, 1m39s; second clean artifact hash set |
| `./gradlew -p publishing/consumer-smoke --write-locks --write-verification-metadata sha256 clean check` | Initial smoke bootstrap PASS; reviewed graph, committed locks and BC-only template |
| `./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check` | PASS; repeated against final staging |
| `./gradlew -PcentralRelease=true :core:signMavenPublication :storage-nio:signMavenPublication --dry-run` | PASS; no tasks executed/upload attempted |
| `./gradlew --offline --no-configuration-cache -I /tmp/j1-signing-audit.gradle -PcentralRelease=true auditSigning` | PASS; signing required for all five artifact types per module |
| `cmp /tmp/j1-repro-first.json build/publication-sha256.json` | PASS, all ten SHA-256 identical |
| Negative VERSION probes via offline `help` | Missing/empty, leading/trailing/embedded whitespace, range, dynamic version, missing final LF all rejected; original VERSION restored |
| Negative coordinate probes via `publishing/verify-publication.py` | Changed NIO core dependency to artifact `core`, recomputed valid checksums; both XML POM and JSON module rejected structurally; original files restored |
| `./gradlew --offline --no-daemon build check test verifyPublication consumerSmoke` | Final credential-free verification PASS |
| `git diff --exit-code HEAD -- SPEC_PIN.md core/src storage-nio/src core/gradle.lockfile storage-nio/gradle.lockfile settings-gradle.lockfile` | PASS, sources/tests/snapshot/pin/existing locks unchanged |
| `git diff --check` | PASS |

Final forced-run test results: **core 346 tests, storage-nio 115 tests; zero
failures, errors or skips**. The one conformance accounting test executes all 90
portable cases, not merely one corpus input. Production bytecode checks also
run in both module `test` and `check` tasks. No corpus outcome changed.

Resolved intermediate failures: duplicate plugin/existing Javadoc archive tasks
(as described above); Python not initially on daemon PATH; initial absent-VERSION
negative probe expected a clearer diagnostic, now provided explicitly. No
validation failure remains. Tests/fixtures were never removed or weakened.

Unavailable/deferred: Nix executable is absent from this environment (despite
Nix-provided JDK/Python paths); no `nix develop`/flake evaluation could be run.
There are no flake build/check outputs, only formatter and dev shells. Actual
Central signing/upload/validation/download and namespace authorization require
operator secrets/actions and were deliberately not run. No Java 17 runtime was
available for execution qualification; production compilation uses `--release 17`
and all 202 production classfiles are verified as version 61. API inventory
baseline was optional and no new API-compatibility tooling was introduced.

CI remains credential-free: existing build/tests plus local publication/verifier,
standalone Gradle metadata consumer, and POM-only consumer. No release workflow
or Central secret was added.

## Final worktree evidence

All changes remain uncommitted. `git status --short`:

```text
 M .github/workflows/ci.yml
 M API_DESIGN.md
 M README.md
 M build.gradle.kts
 M flake.nix
 M gradle.properties
 M gradle/verification-metadata.xml
 M storage-nio/build.gradle.kts
?? RELEASE_CHECKLIST.md
?? VERSION
?? publishing/
?? review/J1_MAVEN_PUBLICATION_REPORT.md
```

`git diff --stat` (tracked-file changes; new files are listed separately below):

```text
 .github/workflows/ci.yml         |   5 +-
 API_DESIGN.md                    |   8 +++
 README.md                        |  31 ++++++++
 build.gradle.kts                 |  72 +++++++++++++++++++
 flake.nix                        |   2 +
 gradle.properties                |   1 +
 gradle/verification-metadata.xml | 150 +++++++++++++++++++++++++++++++++++++++
 storage-nio/build.gradle.kts     |   6 ++
 8 files changed, 274 insertions(+), 1 deletion(-)
```

New files (`git ls-files --others --exclude-standard`):

```text
RELEASE_CHECKLIST.md
VERSION
publishing/consumer-smoke/.gitignore
publishing/consumer-smoke/build.gradle.kts
publishing/consumer-smoke/gradle.lockfile
publishing/consumer-smoke/gradle.properties
publishing/consumer-smoke/settings.gradle.kts
publishing/consumer-smoke/src/main/java/ConsumerSmoke.java
publishing/consumer-smoke/verification-metadata-template.xml
publishing/verify-publication.py
review/J1_MAVEN_PUBLICATION_REPORT.md
```

Ready for operator review and Maven Central 0.1.0 publication
