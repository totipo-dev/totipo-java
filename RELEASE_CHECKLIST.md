# Totipo Java 0.1.1 release checklist

The implementation version comes from `VERSION`; protocol compatibility is
independent. Version 0.1.1 aligns to Totipo Vault Format v1/r18 without portable
behavior changes from the prior r17 pin. Specification revisions do not
mechanically determine the Java semantic version.

Release provenance:

- Maven coordinates: `org.totipo:totipo-core:0.1.1` and
  `org.totipo:totipo-storage-nio:0.1.1`.
- Protocol: v1/r18, specification commit
  `4623a7e1718e23504903096c92332597057bd8f0`; authoritative hashes in `SPEC_PIN.md`.
- Conformance: protocol-foundation core operations, audited facade TOKEN projections
  and metadata handling in create/update/merge (including partial resolution and
  frozen retries), and qualified low-level NIO/core store operations as scoped in
  README. No blanket facade certification or application conformance. The previous
  historical-metadata qualification is resolved by the
  [focused §12 audit](review/V1_R18_CAUSAL_FACT_METADATA_REPORT.md); application-observation
  limitations in API_DESIGN.md remain.
- Portable corpus: 90/90, none deferred; reconfirmed on the exact release commit.
- Java source commit: the operator enters the full reviewed SHA at dispatch. The
  workflow appends it to the GitHub release body, leaving committed reviewed notes
  unchanged. Annotated source tag convention: `v0.1.1`, matching unsigned `v0.1.0`.
- Java 17 production bytecode; builds use pinned Gradle 9.8.0 and JDK 25.
- Qualification limits in README still apply; no new desktop, Android, provider,
  independent interoperability, or security-audit claim follows from publication.

## Preferred procedure: protected GitHub Actions workflow

Use **Release**, [.github/workflows/release.yml](.github/workflows/release.yml).
Its only trigger is `workflow_dispatch`; changing `VERSION` or pushing to `main`
does not publish anything. The architecture intentionally replaces the previous
manual Central Portal publication with protected-workflow automatic publication.

```text
preflight (no release secrets)
  → publish-central (release environment approval → sign → publish and release)
  → verify-central (exact remote bytes and fresh module/POM consumers)
  → tag-and-github-release (annotated source tag → GitHub release)
```

- [ ] Review and commit the complete release source; push the reviewed commit to
  `main` through the repository's usual review process. Keep `main` at that commit
  while releasing; identity checks fail if it moves.
- [ ] Verify `VERSION`, the exact r18 pin, corpus outcomes and reviewed
  `review/V0_1_1_RELEASE_NOTES.md`. A future version needs its own reviewed notes
  and an explicit workflow update; the initial workflow uses the v0.1.1 notes.
- [ ] Confirm authority for the Central namespace `org.totipo`, Portal user-token
  credentials, and a Central-compatible signing key/public-key distribution.
- [ ] Complete the one-time environment setup below.
- [ ] In Actions → **Release** → **Run workflow**, select **main** and enter:
  - `version`: `0.1.1`, exactly matching `VERSION`.
  - `commit`: the full **40 lowercase hexadecimal characters** of the reviewed
    current `main` commit. Abbreviated SHAs are rejected.
- [ ] Review preflight evidence; approve deployment to **release** when prompted.
  Dispatch and protected-environment approval are the intentional human controls
  for irreversible Maven Central publication. Configure required reviewers to
  obtain an approval prompt; declaring an environment alone does not enforce one.
- [ ] Confirm all four jobs succeed. Maven Central is the binary distribution
  channel; the GitHub release has reviewed notes/provenance, without Maven binaries.

Version input follows the repository's `major.minor.patch` grammar with an optional
Maven qualifier; snapshot releases are excluded. Inputs pass through quoted
environment variables, with validation before checkout or command use. The exact
checkout SHA, dispatch SHA, `refs/heads/main`, current fetched `origin/main`, exact
`VERSION`, clean checkout, and committed expected `SPEC_PIN.md` are checked.
Tags and current `main` are fetched explicitly. An existing `v<version>` tag or
GitHub release stops initial preflight. Both canonical Central POM endpoints must
return **404**; **200** means an immutable version already exists. Network errors
and any unexpected HTTP status fail closed.

## One-time GitHub UI setup

In repository **totipo-org/totipo-java**:

1. Settings → Environments → create **release**.
2. Restrict deployment branches to **main**.
3. Configure required review/approval where supported by the repository's GitHub
   plan. For a sole maintainer, leave **prevent self-review** disabled unless
   another reviewer is available. Verify protection is enforced before dispatch.
4. Add these **environment** secrets, never repository source or ordinary CI:

| GitHub environment secret | Existing Gradle environment property |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | `ORG_GRADLE_PROJECT_mavenCentralUsername` |
| `MAVEN_CENTRAL_PASSWORD` | `ORG_GRADLE_PROJECT_mavenCentralPassword` |
| `SIGNING_IN_MEMORY_KEY` | `ORG_GRADLE_PROJECT_signingInMemoryKey` |
| `SIGNING_IN_MEMORY_KEY_PASSWORD` | `ORG_GRADLE_PROJECT_signingInMemoryKeyPassword` |
| `SIGNING_IN_MEMORY_KEY_ID` | `ORG_GRADLE_PROJECT_signingInMemoryKeyId` |

The Central username/password are **Portal user-token fields**, not a Portal login
password. The first three secrets are required. The password is required for an
encrypted private key; omit it only for a genuinely unencrypted key accepted by
the existing signing plugin. Key ID is optional unless the configured key needs
selection. Empty optional fields are unset before Gradle. Key packet inspection
uses stdin and captured memory only; no private-key file is created or imported.
Signing tasks are the authoritative proof that the key/password/selection works.
Missing required secrets are reported by name without their values.

Only `publish-central` references this environment and signing/Central secrets.
Ordinary CI, preflight, remote verification and tagging have no access to them.
`GITHUB_TOKEN` supplies GitHub read access and final tag/release write access;
no additional PAT is required. All checkout credentials remain unpersisted;
final tag push uses an ephemeral process environment for authentication.

## Complete credential-free preflight

Use JDK 25 and Python 3.9+ (standard library only), available in `nix develop`.
The workflow runs the following from the exact commit, with the wrapper JAR
checksum checked and strict dependency verification/locking preserved:

```sh
./gradlew clean test build verifyPublication consumerSmoke
./gradlew --offline --no-daemon --no-build-cache --rerun-tasks \
  clean test build verifyPublication consumerSmoke
./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check
./gradlew :core:test \
  --tests org.totipo.conformance.SpecSnapshotIntegrityTest \
  --tests org.totipo.conformance.R18ProfileIntegrityTest
(cd core/src/test/resources/totipo-spec/v1-pre-rc && sha256sum -c SNAPSHOT.sha256)
git diff --check
git status --short
```

- [ ] Full normal and forced offline suites have zero failures/errors/skips.
  Current evidence is 478 tests (363 core + 115 NIO); the total is recorded,
  not used as the sole acceptance criterion. Explicit executed-set corpus
  accounting proves **90/90**; integrity is **3/3 snapshot + 1/1 profile** and
  **97/97** snapshot records validate.
- [ ] Java 17 production classfile checks, Javadocs, strict dependency verification
  and locks, publication structure/content/scopes, and both consumer modes pass.
- [ ] Exactly 10 unsigned artifacts (six JARs, two POMs, two `.module` files) in
  `build/publication-sha256.json` have equal hashes across normal and forced offline
  builds. Repository-index timestamps and signatures are excluded. The inventory
  is passed between jobs as a small immutable preflight output; each later job
  independently rebuilds and compares it. This is exact-byte verification, not
  an assumption that all JDKs produce identical bytes.
- [ ] Checkout stays clean; production Java, spec snapshot, corpus and expected
  outcomes are unchanged by release machinery.

`verifyPublication` remains the single artifact inventory/structural verifier.
It generates the independent consumer's ignored verification metadata only after
checking staged bytes. External BC hashes remain pinned in its committed template.
The default consumer remains an exclusive local-staging Totipo repository plus
Central for BC; no Maven-local/composite/source fallback exists.

## Protected Central publication and remote verification

After environment approval, the publishing job repeats source/version/current-main
and tag/release absence checks, queries Central again, and rebuilds unsigned
artifacts against preflight. Ordinary Gradle configuration still exposes only
unsigned local staging. Central/signing remain gated by `-PcentralRelease=true`;
no permanent enablement or property-name change is made.

Before upload, it runs:

```sh
./gradlew --no-daemon --no-build-cache --no-configuration-cache \
  -PcentralRelease=true :core:signMavenPublication :storage-nio:signMavenPublication
```

All 10 signing outputs must contain detached `.asc` signatures and their unsigned
inputs must match the reviewed inventory. Then, after a last identity/absence check:

```sh
./gradlew --no-daemon --no-build-cache --no-configuration-cache \
  -PcentralRelease=true publishAndReleaseToMavenCentral
```

This existing Vanniktech 0.37.0 task uploads, validates, and automatically releases
through Central. **Do not manually click Publish for the preferred workflow.**
No generic `publish`, legacy OSSRH or release-wrapper action is used. Gradle daemon
and configuration cache are disabled around secrets; signing remains in memory.

`verify-central` uses no Central credentials. It rebuilds/stages the same commit,
compares to preflight, and polls `https://repo.maven.apache.org/maven2/` for up to
40 minutes, backing off from 10 to 60 seconds. Every downloaded unsigned artifact
must match its freshly built SHA-256 (**10/10**); detached signatures must be
present for all 10 artifacts. Hash mismatch fails immediately. Signature presence
is independently checked; this is not an independent OpenPGP trust certification.

Then the existing independent consumer uses `-PremoteCentral`, and separately
`-PremoteCentral -PpomOnly`, each with a **new temporary `GRADLE_USER_HOME`**.
That mode configures only canonical Central, with no staged Totipo fallback,
`mavenLocal()`, `includeBuild` or source substitution. It verifies exact NIO/core
versions, BC **1.86 runtime-only**, no extra dependencies, compile smoke and
runtime class loading. Strict metadata checks use the inventory already proven
equal to Central. `verifyRepositorySelection` can inspect either configuration
without resolving unpublished Totipo artifacts.

## Tag, GitHub release and retry behavior

Only after exact remote artifacts and both fresh consumers pass does the final job
create/push an **annotated unsigned** `v<version>` at the dispatch commit, matching
`v0.1.0` style. Only that job has `contents: write`; other jobs have `contents: read`.
An existing tag at the exact commit is accepted; a different commit fails and is
never moved or force-pushed. GitHub release creation uses the committed reviewed
notes plus a temporary final source/spec/90-case provenance section. Existing
releases must match the expected tag, title, non-draft/non-prerelease state and
exact body; inconsistent releases fail rather than being overwritten.

- Preflight/approval/signing failure: no Central upload occurs. Fix/review the
  problem; dispatch again if code or the reviewed commit changes.
- Central success followed by propagation/consumer failure: use **Re-run failed
  jobs**. Successful publishing stays completed; only verification and downstream
  jobs rerun. Do not publish again to solve propagation failures.
- Publishing failure after upload may have started: on a rerun of **the same run**,
  public GitHub attempt/job history must prove that its publishing step previously
  started at the same commit. If either GAV is now visible, skip all upload and
  proceed to strict verification of all 10 artifacts. Presence alone is never
  proof of provenance. New dispatches reject existing versions.
- Previous upload may have started but both POMs are still absent: stop rather than
  risking duplicate deployment. Inspect Central Portal, allow propagation, then
  retry the same run once visible. A stuck/failed unpublished deployment requires
  human investigation; automation cannot infer safe deletion or overwrite.
- Tag push succeeded but GitHub release creation failed: rerun the final failed
  job. The exact source tag is reused, then the release is created or verified.
- Any remote hash or inconsistent tag/release discrepancy: stop and investigate;
  immutable Central versions and source tags must never be overwritten.

Anonymous attempt-history reads deliberately preserve minimum GitHub permissions
for this public repository. API/rate-limit failures stop safely. A future private
repository would require a reviewed read-permission change. Release concurrency
is `release` with cancellation disabled; keep it shared by any future release path.

## Emergency fallback: manual operator procedure

Use only after investigating the workflow problem and checking that no release run
or Central deployment is in progress. Repeat all exact-source, absence, build,
signing, inventory and remote-consumer gates above. Keep credentials outside the
checkout as the same `ORG_GRADLE_PROJECT_*` environment variables; never use secret
command-line arguments or secret-bearing repository properties/files. Use the
same signing preflight and explicit **publishAndReleaseToMavenCentral** command.
It automatically releases; do not mix it with manual Portal publishing. Tag and
GitHub release remain after successful remote verification, bound to the reviewed
commit and reviewed notes. Generic `publish` is rejected with the Central flag.

The former `publishToMavenCentral` plus manual Portal Publish process is historical,
not the preferred procedure. See [plugin Central guidance](https://vanniktech.github.io/gradle-maven-publish-plugin/central/).
Desktop migration may begin only after independently downloadable Central artifacts;
no desktop checkout is changed by the release workflow.

A future `VERSION` change may trigger a separate **release-readiness validation**
workflow without secrets, publication, tags or GitHub releases. It must not
publish automatically merely because `VERSION` changed. The manually dispatched,
protected workflow remains the irreversible step unless explicitly redesigned.
