# Totipo Java 0.1.0 release checklist

This is preparation, not a published release. The Maven version is the Java
implementation release version, read from `VERSION`. Protocol compatibility is
independent: this worktree is aligned to Totipo Vault Format v1/r18 without
portable behavior changes from its prior r17 pin. `VERSION` remains 0.1.0;
a reviewed follow-up alignment release would likely be v0.1.1. Future bug fixes may
continue implementing v1/r18; a new specification revision does not mechanically
determine the Java semantic version.

Release provenance:

- Maven coordinates: `org.totipo:totipo-core:0.1.0` and
  `org.totipo:totipo-storage-nio:0.1.0`.
- Protocol: v1/r18, specification commit
  `4623a7e1718e23504903096c92332597057bd8f0`; authoritative hashes in `SPEC_PIN.md`.
- Conformance: protocol-foundation core operations and qualified low-level NIO/core
  store operations as scoped in README; no blanket facade core claim or application
  conformance. Review the retained-history metadata qualification in API_DESIGN.md.
- Portable corpus: 90/90, none deferred. Reconfirm on the final release commit.
- Java source commit: **operator must record the exact reviewed commit here/in
  the release notes after committing, before release**. The preparation baseline
  is not the final release source commit. Tag convention: `v0.1.0`.
- Java 17 production bytecode; builds use pinned Gradle 9.8.0 and JDK 25.
- Qualification limits in README still apply; no new desktop, Android, provider,
  independent interoperability, or security-audit claim follows from publication.

## Source gates

- [ ] Clean worktree; exact Java commit reviewed and recorded.
- [ ] `VERSION` reviewed; both module coordinates match it.
- [ ] Protocol v1/r18 and exact `SPEC_PIN.md` hashes reviewed and unchanged.
- [ ] Complete portable corpus executes 90/90 without skips or changed outcomes.

## Credential-free build and publication gates

Use JDK 25 and Python 3.9+ (standard library only), available in `nix develop`.
Run from the repository root. No global Maven local repository is used.

```sh
./gradlew clean test build
./gradlew --no-daemon --no-build-cache --rerun-tasks clean test
./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test
./gradlew verifyPublication consumerSmoke
./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check
```

- [ ] Clean build, forced rerun, offline rerun, Java-17 classfile checks pass.
- [ ] Strict dependency verification passes; no trusted-all/wildcard exceptions.
- [ ] Strict library dependency locks unchanged. Root plugin buildscript uses
  exact plugin versions and checksum verification; library configuration locks
  do not lock the separate plugin classpath. Review `buildEnvironment` on updates.
- [ ] Javadocs generate at the existing package visibility; warnings reviewed.
- [ ] Local Maven publication under `build/repository` contains only two GAVs.
- [ ] `verifyPublication` passes structural POM/module metadata checks, exact
  `storage-nio -> org.totipo:totipo-core:0.1.0` mapping, scopes, content allowlists,
  Java 17 bytecode and unsigned artifact/checksum inventory.
- [ ] Fixture classifiers, fixture capabilities and fixture dependencies absent.
- [ ] Standalone consumer compiles with module metadata and with POM-only
  resolution. Compile graph: NIO + core; runtime graph adds only BC 1.86.
- [ ] Two clean uncached artifact builds have equal SHA-256 for six JARs, two
  POMs and two `.module` files. Save `build/publication-sha256.json` outside
  `build` between runs, compare, and record the result. Repository index
  timestamps and detached signatures are excluded. This is same-environment
  evidence, not a cross-machine reproducibility guarantee.
- [ ] `git diff --check` passes; production Java changes contain no protocol-semantic changes;
  the exact committed r18 snapshot and independent pins are reviewed; case files
  and expected outcomes are unchanged.

The smoke project is independent, not a root subproject. Its sole requested
dependency reads the implementation version from `VERSION`. An exclusive file
repository supplies Totipo; Maven Central is restricted to BC. No `includeBuild`,
source substitution, sibling checkout, or `mavenLocal()` fallback exists.
Its dependency lock and external BC verification template are committed.
`verifyPublication` generates exact local-artifact verification hashes only after
checking staged content and metadata. This permits differing JDK vendor outputs
without trusting arbitrary repositories or weakening external dependency checks.
Run that task before invoking the standalone consumer directly.

## Central gates — human operator only

Ordinary configuration exposes only unsigned local staging. Central and signing
are enabled together only by `-PcentralRelease=true`. Generic `publish` is rejected
with that flag. Root itself has no publication. No ordinary CI job holds secrets.
Do not set plugin auto-enable properties such as `mavenCentralPublishing` or
`signAllPublications` in a global Gradle properties file for local verification.

- [ ] Operator verifies Central namespace authority for `org.totipo`, corresponding to
  ownership/control of `totipo.org` (operator reports domain ownership; Central
  namespace verification remains a human gate and has not been performed here).
- [ ] Central Portal user token is stored outside the repository as Gradle
  properties `mavenCentralUsername` and `mavenCentralPassword` (token fields,
  not the Portal login password).
- [ ] Signing key is outside the repository. Plugin in-memory properties:
  `signingInMemoryKey`, optional `signingInMemoryKeyId`, and
  `signingInMemoryKeyPassword` when encrypted. Environment equivalents prefix
  each property with `ORG_GRADLE_PROJECT_`. Never print/store secrets in logs.
- [ ] Final reviewed artifacts signed. To prepare signatures without upload,
  use `./gradlew -PcentralRelease=true :core:signMavenPublication :storage-nio:signMavenPublication`.
  Inspect `.asc` signatures for binary, sources, Javadoc, POM and module metadata.
- [ ] Only after review, explicitly upload with
  `./gradlew -PcentralRelease=true publishToMavenCentral`.
  This creates a Central Portal deployment for manual publishing, not an automatic
  release. Check validation in Portal, inspect both GAVs/signatures, then manually
  choose Publish. This is the preferred first-release procedure.
- [ ] Central validation succeeds before the operator releases the deployment.

The plugin also offers `publishAndReleaseToMavenCentral` (with the same explicit
flag here) to upload and automatically release. It is documented for completeness,
**not the selected first-release procedure**. No legacy OSSRH, GitHub Packages,
JitPack, alternate public repository, or namespace-registration action is configured.
No Central upload, deployment creation, release, snapshot publication, or tag is
part of this preparation pass.

Current plugin guidance: [Central Portal](https://vanniktech.github.io/gradle-maven-publish-plugin/central/),
[release compatibility](https://vanniktech.github.io/gradle-maven-publish-plugin/changelog/).

## Post-release gates

- [ ] Both artifacts independently downloadable from Maven Central in a fresh
  consumer without local staging/source substitution.
- [ ] Released artifact hashes recorded and verified.
- [ ] Source tag `v0.1.0` and release notes map to the exact Java commit/version,
  spec commit and 90/90 corpus evidence.
- [ ] Desktop migration may begin only after Central artifacts are independently
  downloadable. No desktop checkout is changed by this milestone.
