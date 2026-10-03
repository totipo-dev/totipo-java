# v0.1.1 release workflow implementation report

## Summary

Added a manually dispatched, protected GitHub Actions **Release** workflow and
credential-free validation of its machinery. **The workflow was not executed.**
Nothing was uploaded/published, no v0.1.1 tag was created or pushed, no GitHub
release was created, and no real secrets or GitHub environment settings were added.
All changes are uncommitted for review.

Starting reviewed source: `6b2ad145d452be15906ff3d64c2ab8ab708689a0`.
The eventual release dispatch must use the new human-reviewed committed SHA,
not that baseline. `VERSION` remains `0.1.1`.

## Previous release model

Ordinary Gradle configuration stages unsigned artifacts locally. A human operator
supplied `ORG_GRADLE_PROJECT_*` Central/signing properties, enabled
`-PcentralRelease=true`, signed, ran `publishToMavenCentral`, reviewed the Central
Portal deployment and manually clicked Publish. The build also already offered
`publishAndReleaseToMavenCentral`, but the previous checklist did not prefer it.

Every existing file under `.github/workflows/` was inspected **before editing**.
The only existing workflow was `ci.yml`; it is unchanged:

| Convention | Existing CI | New release workflow |
| --- | --- | --- |
| Runner | `ubuntu-latest` | `ubuntu-24.04` |
| Checkout | `actions/checkout@v7.0.1`; unpersisted credentials | Same version pinned to full SHA; unpersisted credentials; exact ref and full history |
| Java action | `actions/setup-java@v6.0.1` | Same version pinned to full SHA |
| Java | Temurin JDK 25 | Temurin JDK 25 |
| Wrapper | `./gradlew`; wrapper JAR SHA-256 checked | Same wrapper and same checksum before Gradle in every Java job |
| Dependency verification | Strict committed Gradle verification/locks; offline POM consumer | Preserved, plus full forced offline rerun and Central-only consumers |
| Permissions | Global `contents: read` | Global `contents: read`; only final tag/release job has `contents: write` |
| External action pinning | Version tags, not full SHAs | Every action is pinned to an exact 40-character SHA |
| Shell | Explicit Bash for checksum; other steps default runner shell | Explicit Bash default for all shell steps |

Exact action refs were resolved read-only against the official GitHub repositories:

- Checkout v7.0.1: `3d3c42e5aac5ba805825da76410c181273ba90b1`.
- Setup Java v6.0.1: `de7274f081f381c8f8158605e0321c36c376e2e6`.

No third-party action or new publishing plugin was introduced.

## New release flow

```text
workflow_dispatch on main, explicit version + reviewed commit
  → preflight: exact identity, absence, full credential-free gates, inventory
  → publish-central: release environment approval, revalidation, signing, Central release
  → verify-central: fresh inventory, remote bytes/signatures, fresh remote consumers
  → tag-and-github-release: exact annotated source tag, then GitHub release
```

The irreversible boundary is the human-dispatched, protected-environment publishing
job. The repository administrator must configure required environment review to
make approval mandatory; YAML alone cannot supply protection rules. No push or
VERSION-path publication trigger is present. A future VERSION change may trigger
separate secret-free **release-readiness validation**, with no publication, tag or
GitHub release. This does not change the manually approved irreversible policy.

## Workflow inputs

Both inputs are required strings. `version` follows the committed build's
major.minor.patch/optional Maven-qualifier grammar, excluding SNAPSHOTs; it must
exactly equal `VERSION`, including its single final newline in the file check.
Current expected version is `0.1.1`. `commit` must be exactly 40 lowercase hex
characters; abbreviations, uppercase, trailing whitespace and shell syntax fail.

The shell validates input before checkout uses it. Subsequent checks require:

- Dispatch ref `refs/heads/main`.
- Dispatch SHA == requested commit == checkout HEAD == explicitly fetched `origin/main`.
- Clean checkout; exact committed expected `SPEC_PIN.md` SHA-256, v1/r18 spec
  commit `4623a7e1718e23504903096c92332597057bd8f0`.
- No initial local/remote `v<version>` source tag or GitHub release.
- Both canonical Central GAV POM endpoints return 404; existing versions and
  ambiguous HTTP/network errors fail conservatively.

Tags and current main are explicitly fetched. `main` should remain at the reviewed
commit during the release; identity checks stop if it moves. Operator strings
enter commands only through validated/quoted environment variables or subprocess
argument arrays, never shell expression interpolation.

## Secrets contract

Names only; no values were added or inspected:

| Environment secret | Existing Gradle property environment variable |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | `ORG_GRADLE_PROJECT_mavenCentralUsername` |
| `MAVEN_CENTRAL_PASSWORD` | `ORG_GRADLE_PROJECT_mavenCentralPassword` |
| `SIGNING_IN_MEMORY_KEY` | `ORG_GRADLE_PROJECT_signingInMemoryKey` |
| `SIGNING_IN_MEMORY_KEY_PASSWORD` | `ORG_GRADLE_PROJECT_signingInMemoryKeyPassword` |
| `SIGNING_IN_MEMORY_KEY_ID` | `ORG_GRADLE_PROJECT_signingInMemoryKeyId` |

The first three are required. Password is required for encrypted keys; omission is
allowed only for genuinely unencrypted keys accepted by the plugin. Key ID is
optional if selection is unnecessary. Empty optional properties are unset before
Gradle. Required presence is checked at job start; private-key packet inspection
checks encryption before signing. GPG receives the key on stdin, without import;
packet output remains captured in memory and is never logged. In-memory Gradle
signing tasks prove the configured key/password can sign before any upload.

Only protected publishing steps map these secrets. No `.env`, secret property/key
file, secret command-line argument, key echo, unsigned fallback or global enablement
was added. Secret-bearing Gradle invocations disable daemon, build cache and
configuration cache. The live key/credentials path was not executed locally.

## GitHub environment

One-time human setup for **totipo-org/totipo-java** is documented in
`RELEASE_CHECKLIST.md`: Settings → Environments → create **release**, restrict
branches to **main**, configure required reviewer approval where supported by the
repository/plan, and add the environment secrets above. For a sole maintainer,
leave prevent-self-review disabled unless another reviewer is available.

Only `publish-central` declares `environment: release`. Ordinary CI, preflight,
remote verification and tagging do not reference it. Environment protection and
actual plan support were not configured or independently exercised in this task.

## Central behavior

The workflow preserves the repository's existing Vanniktech **0.37.0** configuration
and uses **`-PcentralRelease=true publishAndReleaseToMavenCentral`**. This explicit
existing task uploads, validates and automatically releases; protected workflow
approval replaces manual Portal Publish as the preferred mechanism. The build's
`automaticRelease = false` default and ordinary unsigned staging are unchanged.
No generic `publish`, permanent Central property, legacy OSSRH or new plugin/action
was added. Task discovery confirmed both modules' signing and Central tasks exist;
no signing or Central upload/publish task was invoked during local validation.

Before upload, the workflow runs both `signMavenPublication` tasks, checks the
10 expected detached signing outputs, and hashes their unsigned inputs against the
reviewed staging inventory. It repeats source/tag/Central checks immediately before
upload. Both post-approval unsigned staging and signed inputs must match preflight.

## Remote verification

`verifyPublication` remains the authoritative inventory generator. Preflight
compares normal and forced offline inventories and passes its small JSON map as a
job output. Publishing and remote verification independently rebuild from the
exact requested commit and compare against that output. No artifact-transfer
action or duplicated hand-maintained artifact filename list is needed.

Verification uses **https://repo.maven.apache.org/maven2/** without Central
credentials. It waits up to **40 minutes**, with **10–60 second** backoff, for the
inventory's 10 unsigned artifacts and their `.asc` signatures. Downloaded hashes
must match freshly rebuilt bytes **10/10** and preflight. A mismatch fails
immediately; only missing (404) artifacts/signatures are treated as propagation.
Unexpected HTTP status/network errors fail safely and can be retried. Repository
index timestamps and signature bytes are excluded from reproducibility equality.
Signature format/presence is checked independently; this does not assert an
independent OpenPGP trust/signature certification.

The existing standalone consumer adds `-PremoteCentral`, retaining unchanged local
repository modes. Remote mode has exactly one repository, canonical Central, and
no staging/Maven-local/source/composite fallback. Each module-metadata/POM-only run
uses its own fresh temporary `GRADLE_USER_HOME`. Both compile and runtime class
loading must pass; exact graph checks enforce NIO/core at the requested version,
BC **1.86 runtime-only**, and no unexpected dependencies or fixture capabilities.
The consumer's strict artifact metadata uses hashes already proven equal to Central;
external BC verification remains pinned by the existing committed template.

Remote repository selection was tested locally without resolving unpublished
Totipo. Live post-publication Totipo downloads/consumption were deliberately not
performed or claimed successful.

## Tag/release behavior

Existing `v0.1.0` was inspected with `git cat-file`: it is an **annotated unsigned**
tag pointing to `1865fd36a05d2153425aa288dc7b17ac80c71a69`, message
`totipo-java 0.1.0`. The new final job preserves that style and creates `v<version>`
at the exact dispatch SHA only after remote artifacts and both consumers pass.
No force push or invented source-tag signing requirement is introduced.

An existing exact tag is reused; a tag elsewhere fails without moving it. GitHub
release creation uses built-in `GITHUB_TOKEN`/`gh` after pushing the tag. The
reviewed `review/V0_1_1_RELEASE_NOTES.md` stays unchanged; a temporary body appends
exact Java source SHA, exact spec SHA and the 90/90 statement. Notes must match the
requested version; the workflow requires reviewed updates for subsequent versions.
Existing releases must match tag/title/body and published non-prerelease state;
inconsistency fails instead of overwriting. Maven binaries are not attached.

## Failure/retry behavior

- Initial preflight, approval, missing-secret or signing failure stops before upload.
- Central success followed by propagation/consumer failure: **Re-run failed jobs**
  reruns verification/downstream work while the successful publishing job stays done.
- A failed publishing attempt may have succeeded partially. On rerun, anonymous
  public GitHub job history must show the **same run ID, earlier attempt, exact
  commit, publishing job and actually started (not skipped) upload step**. If either
  GAV is present, skip upload and require all remote bytes/signatures/consumers to
  pass. A fresh dispatch cannot resume an already-present version.
- If a previous upload may have started but both POMs remain 404, fail rather than
  risking duplicate deployment. Inspect Portal, wait for visibility, then retry the
  same run. Stuck unpublished deployments need human investigation.
- Anonymous history API/network/rate-limit failure stops safely. This design uses
  the repository's public visibility to keep tokens at contents-read; a future
  private repository needs a reviewed permission change.
- Final tag succeeded but GitHub release creation failed: rerun the final job,
  verify/reuse the exact tag and create or verify the release.
- Remote mismatch/inconsistent tag or release stops; immutable versions and tags
  are never overwritten. Concurrent release workflows serialize under `release`,
  with cancellation disabled.

## Security review

Explicit YAML/script review completed:

- `workflow_dispatch` is the only trigger; no `push`, `pull_request_target`, PR
  trigger, VERSION publication automation or PR-selected secret-bearing checkout.
- Exact main SHA is validated before checkout; all later checkouts use the validated
  preflight output. Identity is rechecked after protected approval and before upload.
- All external actions are full-SHA-pinned official checkout/setup-java only.
- Fixed Ubuntu runner, explicit Bash, explicit per-job timeouts, global contents-read;
  only final tagging/release has contents-write. No PAT or broad validation token.
- Release environment/secret references are confined to publishing. No secret value
  is printed, persisted in the checkout/configuration cache, or passed on a CLI.
- Every checkout uses `persist-credentials: false`. Final tag push uses only an
  ephemeral process-environment Git HTTP authentication header, never stored config.
- Input grammar/commit validation and quoting prevent operator-input shell injection.
- Existing in-memory signing is required; no unsigned fallback. Optional blank
  signing fields are handled before Gradle; required encrypted-key password is checked.
- Local and remote consumers use strict dependency verification, no `mavenLocal()`,
  source substitution or composite build; fresh remote caches prevent local Totipo hits.
- Single release concurrency group with no cancellation protects active publication.

## Local validation

Environment: JDK **25.0.4.1+1**, Python **3.14.7**; no production Java edits.
All final checks below passed without Central/signing secrets:

| Command/check | Result |
| --- | --- |
| Baseline `./gradlew clean test build verifyPublication consumerSmoke` before consumer edits | PASS; saved baseline 10-artifact JSON outside `build` |
| `./gradlew -PcentralRelease=true tasks --all` | PASS; both modules expose `signMavenPublication`, `publishToMavenCentral`, `publishAndReleaseToMavenCentral`; task listing only |
| Final `./gradlew clean test build verifyPublication consumerSmoke` | PASS; 478 tests, zero failures/errors/skips, 90/90 portable cases; Java 17/publication/module consumer/runtime smoke |
| Final `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test build verifyPublication consumerSmoke` | PASS; all 30 root tasks executed; same 478/zero/90 evidence; no cache restores |
| `./gradlew -p publishing/consumer-smoke --offline -PpomOnly clean check` | PASS; exact compile/runtime graph and runtime class loading |
| `./gradlew :core:test --tests org.totipo.conformance.SpecSnapshotIntegrityTest --tests org.totipo.conformance.R18ProfileIntegrityTest` | PASS; 4 tests, snapshot 3/3 + profile 1/1, zero failures/errors/skips |
| `(cd core/src/test/resources/totipo-spec/v1-pre-rc && sha256sum -c SNAPSHOT.sha256)` | PASS; 97/97 records; inventory paths are relative to that directory |
| Three `verifyRepositorySelection` invocations: default, `--offline -PremoteCentral`, `--offline -PremoteCentral -PpomOnly` | PASS; local mode retains staging + BC Central; both remote modes configure Central only without dependency resolution |
| `python3 -B -m unittest discover -s publishing -p test_release.py -v` | PASS; 19 mocked tests: malicious/invalid inputs, HTTP ambiguity, same-run partial retries, skipped-step exclusion, hash/signature failures, signing/password presence, conflicting/idempotent/exact tag/release paths |
| Exact dispatch Bash block executed in 8 valid/invalid-input scenarios | PASS; no shell evaluation of injected input |
| All 13 multiline shell blocks checked with `bash -n` | PASS |
| `/tmp/totipo-actionlint-1.7.7 -shellcheck= -pyflakes= .github/workflows/release.yml` | PASS; YAML structure, expressions and workflow references validated; external shellcheck/pyflakes unavailable and disabled |
| Existing wrapper JAR checksum check | PASS; same SHA-256 as CI |
| `cmp` of baseline, final normal and final forced offline publication JSON | PASS; **10/10 names and SHA-256 hashes identical**, no production artifact-byte change |
| `git diff --exit-code` for VERSION, spec pin/snapshot/tests, production Java, build/wrapper/dependency configuration and smoke lock | PASS; unchanged |
| `git diff --check` | PASS |

No workflow linter was initially installed. A temporary actionlint **1.7.7** binary
was downloaded from its versioned official release and verified against that
release's checksum inventory; archive SHA-256
`023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757`.
No tooling dependency was added to the repository. Bash syntax/input tests provide
additional shell validation. GPG secret packet inspection and live signing are
mocked; no real signing key or credential was used. Existing Javadoc completeness
warnings remain; no doclint/build failure. Nix was not available on PATH and no
additional platform qualification is claimed.

An initial consumer repository-selection assertion inspected the project repository
container instead of settings and failed two intermediate builds. It was corrected
to inspect the settings repositories, then all required commands were rerun and
passed. Final full-suite accounting was saved outside `build` before focused tests,
which replace core's live XML with the four-test focused report.

## Files changed

| File | Reason |
| --- | --- |
| `.github/workflows/release.yml` (new) | Protected manual four-job release workflow, pinned actions, strict identity, minimal permissions and retry boundaries |
| `publishing/release.py` (new) | Standard-library identity/absence/retry, inventory/signing/remote-byte/test evidence and final tag/release guardrails |
| `publishing/test_release.py` (new) | Mocked release failure/retry and mutation-order tests, also run by preflight |
| `publishing/consumer-smoke/settings.gradle.kts` | Explicit Central-only mode and repository-selection verification; local repository behavior preserved |
| `publishing/consumer-smoke/build.gradle.kts` | Runtime smoke and repository-selection checks in consumer check task |
| `publishing/consumer-smoke/src/main/java/ConsumerSmoke.java` | Harmless runtime class-loading entry point in consumer fixture only |
| `README.md` | Timeless coordinates/process wording and protected-workflow reference; conformance claims unchanged |
| `RELEASE_CHECKLIST.md` | Preferred workflow, environment/secrets UI setup, complete gates, retries and emergency fallback |
| `review/V0_1_1_RELEASE_WORKFLOW_REPORT.md` (new) | This implementation/security/validation report |

No changes to VERSION, Java protocol/application production semantics, spec pin,
snapshot, corpus cases/outcomes, coordinates, dependency versions, Gradle publishing
configuration, locks, existing CI or reviewed release-note source.

## `git diff --stat`

```text
 README.md                                          |  22 +-
 RELEASE_CHECKLIST.md                               | 319 ++++++++++++++-------
 publishing/consumer-smoke/build.gradle.kts         |   7 +
 publishing/consumer-smoke/settings.gradle.kts      |  51 +++-
 .../src/main/java/ConsumerSmoke.java               |  10 +-
 5 files changed, 289 insertions(+), 120 deletions(-)
```

Git's ordinary diff stat excludes the four untracked new files listed above;
none were staged merely to make them appear in this stat.

## `git status --short`

```text
 M README.md
 M RELEASE_CHECKLIST.md
 M publishing/consumer-smoke/build.gradle.kts
 M publishing/consumer-smoke/settings.gradle.kts
 M publishing/consumer-smoke/src/main/java/ConsumerSmoke.java
?? .github/workflows/release.yml
?? publishing/release.py
?? publishing/test_release.py
?? review/V0_1_1_RELEASE_WORKFLOW_REPORT.md
```

## Manual setup still required

- Human review/commit and normal push of the completed release machinery to `main`.
- Create/configure the **release** GitHub environment, including main-only deployment.
- Add the required environment secrets; add optional signing fields only if needed.
- Configure required reviewer approval where supported; for a sole maintainer,
  leave prevent-self-review disabled unless a second reviewer is available.
- Confirm Central namespace/token and signing-key/public-key requirements externally.

## Release readiness

Suitable to dispatch for **v0.1.1 after human review/commit and GitHub environment
configuration**, using that exact committed current-main SHA. Local release gates,
artifact equality, workflow lint and mocked guardrails pass. Protected environment,
live signing/Central release, remote Totipo propagation/consumption, tag push and
GitHub release creation remain intentional live execution requirements; they were
not exercised and are not represented as completed here.

**Do not interpret this report as a publication.** No release workflow, v0.1.1 tag,
Central deployment, GitHub release, push or Git commit was performed by this task.
