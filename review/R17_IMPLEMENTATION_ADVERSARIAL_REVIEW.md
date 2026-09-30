# Totipo Java r17 — whole-implementation adversarial review

Review-only milestone after Phase 5. No implementation, test, build, specification, or visibility changes were made. No commit, push, tag, or release was performed.

## 1. Executive assessment

The implementation is small, largely coherent, and a useful foundation for API work, but **it should not receive an unqualified as-is approval**. One provider-dependent protocol defect needs correction: canonical lookup through a case-insensitive filesystem can accept alternate-case entries that discovery rejects. A temporary provider probe reproduced exact-existing publication success for an object that the same implementation then omits from discovery, and opening uppercase-only `VAULT` through the lowercase canonical lookup.

The executable baseline supports **90/90 portable corpus cases**, with **297 tests, zero failures/errors/skips**, **45 production Java files**, and **2,255 physical production lines**. These facts do not prove every filesystem's naming semantics. The new defect is outside the pinned corpus's tested platform coverage, not evidence that its 90 cases were merely counted without execution.

Findings: **1 BLOCKER, 0 HIGH, 2 MEDIUM, 3 LOW**. The medium issues are unauthenticated filename hash-collision amplification and VAULT result/error taxonomy that would be costly to freeze. Localized issues concern secret-derived string output, stale documentation, and undisclosed platform assumptions in tests.

No cryptographic construction mismatch, arbitrary conflict winner, lost metadata, active DEVICE/provenance machinery, production dependency cycle, deliberate overwrite of an observed existing initial VAULT, or automatic rollback after ambiguous persistence was found. Rewrap ordering and the accepted compare/replace race are correctly implemented on the reviewed case-sensitive filesystem. The next milestone should be targeted remediation and provider qualification, followed by public-API design; no protocol redesign is needed.

## 2. Reviewed baseline

The first two commands were `git status --short` and `git rev-parse HEAD`.

Complete starting status: **empty output**; no staged, unstaged, or untracked paths.

```text
HEAD: 86eecbd73fbffee161bf74e56b065998bdef2cea
Commit subject: move to r17: phase 5
Phase 5: committed, not uncommitted implementation changes
```

The repository does not contain the Phase 1–5 reports linked by README. They were not available as evidence and were not assumed to establish correctness. Source, tests, the normative snapshot, and command results were reviewed directly.

| Observed item | Result |
| --- | --- |
| `./gradlew clean test build` | Passed; Javadoc emitted missing-comment/parameter warnings |
| Isolated `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test` | Passed, 297 tests |
| Core tests | 252, zero failures/errors/skips |
| storage-nio tests | 45, zero failures/errors/skips |
| Manifest-derived executed inventory | 90/90; no deferred categories |
| Production sources | core 39 files; storage-nio 6 files; total 45 |
| Physical production LOC, including blanks/comments | 2,255 |
| Production bytecode | Both verification tasks passed, major 61, minor 0 |
| External production runtime dependency | `org.bouncycastle:bcprov-jdk18on:1.86` only |
| Build runtime | OpenJDK Nix 25.0.4.1; Gradle 9.8.0 |
| Initial snapshot verification | All 97 imported files passed |
| Focused integrity tests | `SpecSnapshotIntegrityTest` and `R17ProfileIntegrityTest` passed |

One attempted offline run was invalidated by **reviewer-induced overlapping Gradle test tasks**: the focused integrity invocation started before the first offline invocation fully exited. That run failed with `NoSuchFileException` for `core/build/test-results/test/binary/in-progress-results-generic.bin`. It is not counted as a passing run or classified as a repository defect. All invocations were allowed to finish; the full offline command was then rerun alone and passed. The isolated run is the baseline used here. There was no independently observed baseline failure requiring termination of the implementation review.

### Exact protocol pin

`SPEC_PIN.md`, the snapshot's normative header, manifest, and requirements profile identify **r17**, upstream commit **`1d42a481f230e0adbb89dbeaa936d3c956e70fdc`**. All five expected hashes were independently checked with `sha256sum`:

| Artifact | Observed SHA-256 |
| --- | --- |
| `spec/totipo-vault-format-v1.md` | `f8d2ab02c97e8ac54847048a06cb088359db982fec3f176fd473ce0f223d43cf` |
| `vectors/manifest.json` | `94fff22842573e15b254bb0653970761c15cf122192947a36fccc48344a84f08` |
| `vectors/manifest.schema.json` | `e7a5d8ec0392e0248ab867375b7c907a7ca1298595acdb14ecd3edcbe66df476` |
| `vectors/case.schema.json` | `d38618f53dcf0a558c389831e8838a07248066beff392812f3d277cc974e25c9` |
| `requirements/v1-pre-rc.json` | `ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e` |

The commit identifier is the repository's recorded provenance; this review verifies the local pinned bytes, not a fresh upstream checkout. No newer Totipo specification was fetched, and no Go implementation was consulted as an oracle. Limited external research used authoritative JDK documentation solely to clarify filesystem/provider semantics.

## 3. Architecture reconstructed from source

In source references below, `C/` means `core/src/main/java/dev/totipo/format/`, and `N/` means `storage-nio/src/main/java/dev/totipo/storage/nio/`. Test references use their real class names and module; all production files are inventoried here.

```text
Application composition (not yet designed)
  ├─ VaultLifecycle -> VaultBootstrapWriter / VaultUnlocker
  │                    -> PasswordBytes / VaultBootstrap / Argon2idKdf
  │                    -> VaultUnlockResult -> CryptoSupport
  │  └─ VaultBootstrapStorage / VaultBootstrapReplacementStorage
  ├─ TokenStoreReader -> DiscoverySource -> bounded bytes
  │                    -> EnvelopeReader -> TokenReader -> ValidatedToken
  │  └─ TokenStoreObservation -> explicit TokenGraph.evaluate
  ├─ TokenPublicationPlan -> TokenFold -> TokenWriter -> keyed stage IDs
  │  └─ TokenPublisher -> V1EnvelopeWriter -> V1ObjectPublicationStore
  └─ Totp -> complete TokenValue.Credential, independent of graph policy

storage-nio -> core SPIs and ObjectId
  NioDiscoverySource / NioV1ObjectPublicationStore / NioVaultBootstrapStorage
    -> NioFiles
    -> StorageDurability, normally NioDurability

core -> JDK crypto + BC lightweight Argon2id only
core tests -> storage-nio main + its test fixtures (test-only reverse edge)
```

### Complete production source inventory and responsibilities

| Area | Types reviewed | Responsibility / visibility |
| --- | --- | --- |
| VAULT orchestration | `VaultLifecycle`, `VaultUnlockResult` | Package-private lifecycle coordination, statuses, owned closeable root |
| VAULT bytes and crypto | `PasswordBytes`, `VaultBootstrap`, `VaultBootstrapWriter`, `VaultUnlocker`, `Argon2idKdf`, `BouncyCastleArgon2idKdf` | Package-private strict input, fixed representation, wrap/unwrap, fixed KDF seam |
| VAULT SPI | `VaultBootstrapStorage`, `VaultBootstrapReplacementStorage` | Public cross-module observation/staging/install capabilities |
| TOKEN domain | `TokenId`, `TokenValue`, `TokenMetadata`, `TokenObject`, `UInt64`, `SecurityBytes` | Package-private owned immutable semantic values and validation |
| Identity | `ObjectId` | Public solely where needed by storage SPIs; keyed construction remains hidden |
| TOKEN codec | `TokenReader`, `TokenWriter`, `StrictUtf8`, `ByteCursor`, `TlvField`, `TlvReader`, `TlvWriter` | Package-private exact grammar, framing, bounds, scratch ownership |
| Crypto/envelope | `CryptoSupport`, `EnvelopeReader`, `V1EnvelopeWriter`, `Totp`, `EntropySource` | Package-private primitives, envelope validation/sealing, TOTP, CSPRNG seam |
| Graph | `ValidatedToken`, `TokenGraph` | Package-private trusted facts and pure per-identity SCC/current-state derivation |
| Authorship | `TokenFold`, `TokenPublicationPlan`, `TokenPublisher` | Package-private complete assertions, deterministic stages, ordered immutable publication |
| Observation | `BoundedObjectRead`, `TokenStoreReader`, `TokenStoreObservation` | Package-private bounded read/validation and descriptive results |
| TOKEN SPI | `DiscoverySource`, `V1ObjectPublicationStore` | Public storage observation and immutable publication contracts |
| NIO providers | `NioDiscoverySource`, `NioV1ObjectPublicationStore`, `NioVaultBootstrapStorage` | Public concrete adapters, no crypto interpretation |
| NIO support | `NioDurability`, `StorageDurability`, `NioFiles` | Public injectable directory capability and default implementation; package-private file helpers |

These are 45 top-level types/files: 10 public and 35 package-private. The package-private orchestration types are the lifecycle, unlocker/writer, store reader/observation, graph/validated facts, fold/plan/publisher, and envelope/codec helpers listed above. Important nested internal types are `VaultLifecycle.CreationResult`, its enums, `VaultUnlockResult.Status`, `EnvelopeReader.Result/Status`, `TokenGraph.Result/View/UnresolvedParent/CurrentValueState`, `TokenFold.Stage`, `TokenStoreObservation.CandidateDiagnostic/Reason`, `TokenValue.Credential`, `V1EnvelopeWriter.ObjectBytes`, `TlvReader.Result/Status`, `TlvField`, `ByteCursor.TruncatedInput`, and `EntropySource.Jdk`. NIO's `Operations` seams and `NioFiles.Writer` are package-private; `NioVaultBootstrapStorage.Stage` and `TlvWriter.Buffer` are private.

The major separations earn their existence: bytes versus semantic grammar; observation versus graph interpretation; explicit authorship versus storage; lifecycle authorization/order versus opaque NIO staging. No new framework or persistence layer is indicated.

## 4. Findings summary

| ID | Severity | Area | Summary | Fix before |
| --- | --- | --- | --- | --- |
| F1 | BLOCKER | NIO canonical names | Case-insensitive lookup accepts noncanonical entries; exact-existing publication can succeed for an object discovery ignores | before commit / next approval of Phase 5 |
| F2 | MEDIUM | resource robustness | Chosen unauthenticated ObjectId hash collisions make discovery duplicate checking superlinear | public API |
| F3 | MEDIUM | error/API boundaries | VAULT open result mixes storage and crypto; write `FAILED` loses known-failure versus ambiguity distinctions | public API |
| F4 | LOW | secret formatting | `SecurityBytes` inherits a `toString` that exposes its content-derived hash | public API |
| F5 | LOW | documentation | Current pin says 69/90, README links absent reports, and production comments retain stale revision/section references | public API |
| F6 | LOW | test portability | Full test command assumes POSIX/case-sensitive capabilities despite generic JDK build instructions; two tests can skip | desktop/Android |

“Before commit” is a remediation recommendation, not a request to rewrite history: Phase 5 was already committed at the start. No commit was made here.

## 5. Detailed BLOCKER / HIGH findings

### F1 — canonical spelling is not enforced at direct NIO lookup boundaries

**Severity:** BLOCKER. **Classification:** implementation defect conditional on storage-provider naming semantics; protocol defect under r17 §§3 and 18. **Timing:** before commit / next acceptance of the current implementation; also before claiming desktop provider support.

**Affected files/classes and concrete evidence:**

- `N/NioVaultBootstrapStorage.java:43–48` resolves the literal `vault`, checks regular-file type, then reads. It does not establish the actual directory-entry spelling. Replacement uses the same lookup at lines 86–88.
- `N/NioDiscoverySource.java:23–26` checks the type of literal `objects-v1` without checking actual namespace spelling. Lines 31–34 do correctly validate the actual enumerated object filename.
- `N/NioV1ObjectPublicationStore.java:41–49,57–59` accepts an existing namespace and compares the target reached by a lowercase path without checking the entry's actual spelling.
- `N/NioFiles.java:18–24,29–31` enforces types/no-follow, not spelling.
- r17 §3 requires exact case-sensitive canonical names and excludes alternate-case bootstrap aliases and non-lowercase object candidates. §18 requires success at the canonical object target.

**Reproduction:** an external `/tmp` review probe provided case-insensitive path lookup over a temporary local backing directory, while enumeration preserved actual stored names. It used the unchanged production classes and a real `V1EnvelopeWriter` object. With only the uppercase object filename present, it observed:

```text
uppercase-only object publication=ALREADY_PRESENT_EXACT
uppercase-only object observed=0
uppercase-only VAULT opened=true
```

The exact-existing path requested no persistence capability, so an unsupported directory-force implementation does not incidentally protect this path. The uppercase VAULT probe establishes storage selection before crypto; supplying valid wrapper bytes would take that same selected stream into the unlocker. A namespace named only `OBJECTS-V1` has the analogous direct-lookup problem.

This is a **provider-semantic probe**, not a claim that Windows or macOS was run. The test host is case-sensitive. Its modeled behavior is supported by the JDK's explicit recognition of case-insensitive lookup and actual-case path names. [JDK `Path.toRealPath`](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Path.html#toRealPath(java.nio.file.LinkOption...)).

**Why it matters / consequence:** a trusted case-insensitive filesystem needs no attacker racing syscalls to produce this outcome. Publication and observation disagree about which objects exist in the protocol namespace; automatic VAULT opening can select a forbidden alias. The current backend accepts such providers without an explicit exclusion, so passing the Linux tests is insufficient to claim the implementation enforces these semantics generally. No AEAD bypass or root disclosure is involved.

**Minimal remediation:** establish exact actual names for the canonical namespace, bootstrap, and existing object target before interpreting/acknowledging them, or explicitly detect and reject unsupported provider/store naming behavior. Preserve no-follow/type checks, no-replace installation, and read-only exact-existing behavior. Do not rename or “repair” alternate-case entries during ordinary publication. Add a case-insensitive provider regression and qualify at least one actual target platform. This does not require a protocol change or native code.

**HIGH findings:** none identified.

## 6. Detailed MEDIUM findings

### F2 — unauthenticated filename hash collisions amplify discovery cost

**Severity:** MEDIUM. **Classification:** implementation robustness / DoS risk. **Timing:** before public API, preferably with F1's focused remediation.

**Affected files/classes and concrete evidence:** `C/ObjectId.java:46–51` uses content equality and `Arrays.hashCode(bytes)` but is not `Comparable`. `C/DiscoverySource.java:43–46` first sorts candidates, then inserts every ID into a `HashSet` to reject duplicates. `N/NioDiscoverySource.java:31–46` constructs that snapshot from unauthenticated filenames before any size/AEAD validation. Thus an external store can choose all these hash keys without possessing the root.

A 32-byte ID made from sixteen pairs, each either `(0,31)` or `(1,0)`, produces 65,536 distinct IDs sharing the same `Arrays.hashCode`: each pair has the same `31*a+b` contribution. JDK hash-map tree bins do not provide ordinary ordered-key lookup bounds for these equal-hash, non-comparable keys. The external probe constructed public `DiscoverySource.Candidate` values; no opener was called:

| Candidate count | Ordinary IDs, snapshot ms | Colliding IDs, snapshot ms |
| --- | ---: | ---: |
| 4,000 | 11.13 | 75.28 |
| 8,000 | 36.40 | 319.09 |
| 16,000 | 55.13 | 3,409.42 |

These are illustrative single-process timings, not a performance guarantee. The collision construction and source path establish the issue independently of exact timings.

**Why it matters / consequence:** invalid or empty files can cause much greater CPU cost than enumeration, bounded reading, and rejection require. It is not a cryptographic collision and does not forge TOKEN state. This merits MEDIUM rather than BLOCKER: the demonstrated failure is avoidable availability amplification, not changed protocol values or unsafe persistence.

**Minimal remediation:** duplicate-check adjacent IDs in the already sorted snapshot instead of hashing them again. Review other attacker-controlled hash collections when implementing resource controls; `TokenId` partitions and `TokenValue` sets can also have chosen Java hashes, but authenticated values require a root holder and have a different threat exposure. Preserve exact equality and existing semantic ordering; no new dependency or arbitrary protocol object limit is needed. Add a collision-shaped regression that checks behavior/operation bounds rather than a fragile wall-clock threshold.

### F3 — VAULT result responsibilities and failure certainty should not be frozen

**Severity:** MEDIUM. **Classification:** API-design concern / error-taxonomy debt, not current r17 safety failure. **Timing:** before public API.

**Affected files/classes and concrete evidence:**

- `C/VaultUnlockResult.java:3–5` describes a cryptographic unwrap result with no storage lifecycle, yet its enum includes `ABSENT` and `UNAVAILABLE`.
- `C/VaultLifecycle.java:43–51` returns this result for canonical storage observation.
- Creation uses only `CREATED/FAILED` (lines 14,54–76). Existing canonical state, invalid input, stage validation failure, and ambiguous install failure all become `FAILED`.
- Rewrap uses `SUCCESS/STALE/FAILED` (lines 13,79–112). Wrong password, malformed BASE, unavailable CURRENT, unsupported atomic replacement, and failure after the move/directory barrier all become `FAILED`.
- `C/V1ObjectPublicationStore.java:13–15` intentionally treats IO failure conservatively as ambiguous; `TokenPublisher` propagates it. This is internally safer than treating every error as known absence.

**Why it matters / consequence:** a future application cannot distinguish an actionable authentication/input problem from uncertain persistence using the lifecycle result alone. It risks presenting “password unchanged” after the new wrapper actually won. Merely renaming `VaultUnlockResult` would not recover the information discarded by create/rewrap. Conversely, `AUTHENTICATION_FAILED` correctly does not claim certainty that the password, rather than authenticated wrapper bytes, was wrong.

**Recommended remediation:** keep cryptographic unwrap facts separate from storage/lifecycle outcomes at the future composition boundary; preserve known pre-mutation failures and ambiguous post-attempt outcomes as distinguishable information, including capability failures where useful. Retain the conservative no-success/no-rollback behavior. Do not expose the present enums directly and later retrofit certainty into their meaning. This report deliberately specifies no public signatures.

## 7. LOW findings and observations

### F4 — default secret-container string exposes a Java hash of its contents

**Severity:** LOW. **Classification:** localized secret-handling/API misuse concern. **Timing:** before public API.

**Evidence:** `C/SecurityBytes.java:6–20` overrides content `hashCode` but not `toString`. Inherited `Object.toString` therefore includes that content hash in hexadecimal. An external package-local probe printed:

```text
fixture byte 0:   dev.totipo.format.SecurityBytes@1f
fixture byte 1:   dev.totipo.format.SecurityBytes@20
fixture byte 42:  dev.totipo.format.SecurityBytes@49
fixture byte 127: dev.totipo.format.SecurityBytes@9e
```

**Consequence:** direct formatting leaks a deterministic unsalted checksum; a one-byte format-valid secret is recoverable from it. No production logging call site was found, and `TokenValue`, `Credential`, and `TokenObject` explicitly redact their strings, which limits severity. This is not a finding that records currently print the raw secret array.

**Remediation:** explicitly redact `SecurityBytes.toString` and check direct as well as containing-model formatting. Keep content equality/hash semantics needed by value collections. No API redesign is needed.

### F5 — current documentation contains stale state and broken evidence links

**Severity:** LOW. **Classification:** documentation concern. **Timing:** before public API.

**Evidence:** `SPEC_PIN.md:29–34` still says 69/90 implemented and storage/vault deferred, contradicting README and executable inventory. `README.md:16,91–95` links `R17_PHASE5_VAULT_REPORT.md` and three r16 phase reports; none exists in the starting tracked/untracked tree. Ten production comments still describe r16 (`PasswordBytes`, `VaultBootstrap`, `VaultBootstrapWriter`, `VaultUnlocker`, `CryptoSupport`, `TokenReader`, `TokenWriter`, `TokenValue`, `TokenGraph`, `TlvReader`). `ObjectId.java:7` cites §13 for identity, and `V1EnvelopeWriter.java:9` cites §§13–14 for the envelope, where current r17 uses §§10–11.

**Consequence:** a reader cannot reliably distinguish the current milestone from historical evidence. The bytes are nevertheless correctly pinned; this does not invalidate the hash checks.

**Remediation:** update the current coverage sentence; restore legitimate report destinations or remove/repoint broken links; use v1 terminology and current section references for unchanged protocol mechanics. Historical spec history is not a defect and should remain historical.

### F6 — the full test command has platform assumptions not expressed by README

**Severity:** LOW. **Classification:** test-architecture / build-documentation concern. **Timing:** before desktop/Android.

**Evidence:** `core/.../VaultNioWorkflowTest.java:118` invokes external `mkfifo`; `TokenNioWorkflowTest.exactExistingIsReadOnlyAndCollisionRemainsUntouched` uses POSIX permissions; several integration tests create symlinks and assume accepted directory force. `VaultNioWorkflowTest.orphanObjectsAndBootstrapLookalikesNeverGateOrChangeCanonicalWorkflows` assumes `VAULT` and `vault` can coexist. `storage-nio/.../NioDurabilityTest.java:51` and `NioDiscoveryTest.java:115` can abort with JUnit assumptions if symlink fixtures cannot be created. README's JDK-only build alternative does not state these full-suite prerequisites.

**Consequence:** this run had zero skips, but that is not a universal zero-skip guarantee. A non-POSIX or case-insensitive host may fail/skip tests for environmental reasons; worse, F1's naming behavior lacks a dedicated cross-provider assertion. No timing sleeps or current-wall-clock dependence was found.

**Remediation:** document the supported full-suite environment; separate required portable semantic checks from explicitly qualified provider integration checks, with visible capability reporting. Add target-platform CI before claiming portability there. Do not silently skip normative corpus expectations.

### Observations with no required implementation change

| ID | Evidence / assessment | Consequence and recommendation | Timing |
| --- | --- | --- | --- |
| O1 | `TokenFold.java:27–28` intentionally treats input as a set; `TokenPublicationPlan.java:34–38` rejects duplicate caller parents first | Silent deduplication remains only below the checked authorship boundary. Keep it hidden or clarify the internal set contract; not a current caller-path defect | public API composition |
| O2 | `core/build.gradle.kts` has test-only main/test-fixtures dependencies on storage-nio | Acceptable temporary package-private integration organization. Migrate application-facing cross-module tests when the public composition boundary exists; do not make internals public merely to move tests | before API freeze if practical |
| O3 | `VaultLifecycle.cleanup` catches cleanup exceptions; staged SPI docs make close non-durable and non-gating | No failed operation is converted to success. Temporary encrypted wrappers can remain after cleanup failure; ordinary observation ignores them. Preserve this distinction | later provider hardening |
| O4 | `SecurityBytes` is immutable and not wipeable; graph views/plans share `TokenValue` | Closing the root result is not closing/wiping all credential models. Decide application session/credential lifetime before promising session erasure; do not add mutable wipe into hash keys casually | public API ownership decisions |
| O5 | `EntropySource` and `Argon2idKdf` are package-private; defaults use SecureRandom/fixed BC parameters | Hypothesis of public entropy injection is dismissed. Keep these test seams internal | public API |
| O6 | `EnvelopeReader.Result.clear` and `TlvField.clear` do not establish a closed state; array records use array identity equality | Internal synchronous scratch types, not immutable user results. Current consumers do not compare them as values or reuse cleared bytes as validated tokens. Keep hidden | public API |

## 8. Protocol-to-code traceability

| r17 invariant | Enforcing production path | Assessment |
| --- | --- | --- |
| Exact 87-byte VAULT, magic/version before KDF | `VaultBootstrap.parse:16–30`; `VaultUnlocker.unlock:20–28`; `VaultLifecycle.read:134–136` | Enforced; at most 88 observed bytes discriminate long input |
| Password 0..1024 strict UTF-8, no transformations | `PasswordBytes.valid/encode`; writer/unlocker preflight | Enforced; no password String/default charset |
| Fixed Argon2id v0x13, 65536 KiB, 3 iterations, 4 lanes, 16 salt, 32 output, empty K/X | `BouncyCastleArgon2idKdf.derive:10–39` | Enforced |
| Bootstrap GCM header AAD, supplied salt/nonce, 32-byte root | `VaultBootstrapWriter.encode`; `VaultUnlocker.unwrap` | Enforced; generated entropy comes from lifecycle |
| Same root across rewrap and root fingerprint | `VaultLifecycle.changePassword:84–96`; `validates:122–129`; `CryptoSupport.vaultFingerprint` | Root is authenticated BASE root; no rewrap root draw |
| HKDF and domain-separated keyed IDs/object keys | `CryptoSupport.extract/idKey/objectRoot/objectKey`; `ObjectId.compute/authenticates` | Matches §10 |
| 1008-byte encryption plaintext + 16 tag, 1024 physical | `EnvelopeReader:12–16,59–60,79–95`; `V1EnvelopeWriter:20–38` | Enforced |
| Semantic length, zero padding, matching keyed ID | `EnvelopeReader:80–95` | Enforced before semantic parsing |
| ID-derived nonce/AAD, per-object key | `EnvelopeReader.nonce/aad`; reader/writer derivation | Shared derivation; no independent random object nonce |
| Exact TLV grammar, MAX_PARENTS=4, ascending unique parents | `TokenReader.read/field`; `TokenObject:9–24` | Unknown, duplicate, reordered, trailing fields rejected |
| Complete TokenValue including tombstone | `TokenReader:22–49`; `TokenObject` calls `TokenValue.validate` | No inherited or omitted credential fields |
| Optional exact CLIENT_NAME/CLIENT_TIME | `TokenMetadata`, `StrictUtf8`, `UInt64`; reader/writer | Absence/empty/zero/u64-max distinct and preserved |
| Missing/wrong-identity/excluded parent unresolved | `TokenGraph.derive:85–103` | Index restricted to one TOKEN_ID; no ancestry shortcuts |
| Same-ID contradiction | `TokenGraph.evaluate:55–64` | Excludes identity across all partitions; references unresolved |
| SCC causal equivalence/current groups/all member heads | `TokenGraph.derive:105–167` | Iterative Kosaraju, historical target components marked |
| Whole-state conflict independent of metadata | `TokenValue/Credential/SecurityBytes` equality; graph value set | All seven value fields participate, metadata does not |
| Fixed linear carry and same value/metadata | `TokenFold.build:27–50` | First four then carry+three; actual HMAC intermediate IDs |
| Observed configured store only; no global diagnostic gate | `NioDiscoverySource`; `TokenStoreReader`; separate graph call | Relative observations; F1/F2 caveats |
| Immutable complete publication, NEW/EXACT, ambiguity | `TokenPublisher:16–30`; NIO store `publish:35–64` | No graph persistence/rollback; exact-existing F1 caveat |
| Canonical absence before creation entropy, no overwrite | `VaultLifecycle.createNew:59–69`; NIO hard link | Enforced on qualified namespace; objects-v1 not consulted |
| Authenticate BASE before rewrap mutation; exact CURRENT compare | `VaultLifecycle.changePassword:84–103` | Enforced; fingerprint never substitutes for BASE |
| Separate replacement, atomic backend attempt, directory barrier | `NioVaultBootstrapStorage.stage/replaceCanonicalDurably` | Provider-dependent capability; no unsafe fallback |
| TOTP SHA-1/256/512, u64 counter, decimal width | `Totp.generate/timeStep/encodeCounter/truncate/decimalCode` | Credential-only computation; no tombstone/conflict gate |

The principal invariant enforced only by an environmental assumption rather than full code is **actual canonical spelling under aliasing filesystems (F1)**. New-token identity entropy, root preservation, exact metadata, and fold reachability are enforced in production paths, not just comments. `ValidatedToken` itself is an internal trust boundary, not a cryptographic proof constructor; production obtains it only after composed validation, while graph tests intentionally supply symbolic facts.

## 9. Crypto and secret-ownership assessment

The domains are exact ASCII without NUL: `totipo/v1/object-id`, `totipo/v1/object-key-root`, `totipo/v1/object-key`, `totipo/v1/object`, and `totipo/v1/vault-fingerprint`. HKDF extract uses 32 zero bytes as salt; expansion follows HMAC chaining and a one-byte counter. Protocol uses request one 32-byte block. Bootstrap header construction and parsing agree on 39-byte AAD. GCM decrypt emits no incremental plaintext to a parser before successful tag verification. TOTP chooses the three prescribed HMACs, uses unsigned counter encoding and digest-tail offset truncation, and accepts complete tombstone credentials.

No duplicate cryptographic algorithm implementation was found. HKDF is composed from JCA HMAC once; bootstrap and TOKEN GCM calls have genuinely different contexts. BC is used only for lightweight Argon2id, with a new operation-local generator and parameters, and no global provider registration. There is no default-charset conversion or password normalization. The deterministic object key/nonce pair is intentional per keyed identity, not accidental nonce reuse.

### Ownership ledger

| Material | Borrowing/copying | Disposal / limits |
| --- | --- | --- |
| Caller password bytes | Borrowed synchronously by lifecycle/writer/unlocker/KDF; not retained | Caller clears; must not mutate during call |
| Caller password chars | Borrowed by strict encoder; encoder scratch and returned owned encoding are separate | Scratch wiped; char-unlock wipes encoding in finally; caller clears original chars |
| K_root input | Borrowed by crypto/fold/publisher; root array not retained in plans | Caller owns and wipes; no concurrent mutation |
| Generated/recovered K_root | Local owned lifecycle/unwrapper buffer; successful result clones it | Locals wiped in finally; `VaultUnlockResult.close` wipes owned clone; getters return caller-owned copies |
| K_wrap | KDF returns owned array | Writer/unlocker wipe on success/failure, including invalid output length |
| HKDF PRK, K_id, K_object_root, K_object | Operation-local owned arrays | Reader/writer/fold finally blocks wipe; providers may copy |
| HKDF intermediate blocks | Local owned `previous` | Wiped between blocks and on exit; output transferred to caller |
| TOTP secret model | `SecurityBytes` copies input; getters clone; immutable shared value | No close/wipe for retained model; lifetime extends through graph/plan/value references (O4) |
| TOTP HMAC scratch | Copied secret, counter, digest | Wiped in `Totp.generate` finally |
| TOKEN P / padded plaintext | Writer returns owned bytes; envelope and field results own copies | Publisher/fold/store reader wipe P; envelope clear disposes retained P; reader/writer wipe scratch |
| Bootstrap candidate / BASE / CURRENT | Lifecycle-owned read/encoded arrays; NIO stages clone candidate | Lifecycle finally clears available arrays; NIO stage clears its write copy; encrypted representation may remain in storage/buffers |
| Salt / nonce | Lifecycle owns independent arrays; bootstrap returns copies; parameters clone salt | Lifecycle wipes local arrays; unwrap wipes local salt; BC builder/parameters clear; public header copies need no secrecy claim |
| Fingerprint / ObjectId | Non-secret recognition/address data, copied as needed | Not a freshness/authorization token; no secure-erasure requirement |

Read-only bootstrap and envelope objects take defensive snapshots of mutable caller representations. Root/password arguments are intentionally borrowed, not retained. No returned backing byte array or mutable input-backed model collection was found. Optional values are immutable Strings/UInt64; nested graph groups and maps/sets are copied/unmodifiable. Plan stages hold complete values, including credentials, despite correctly retaining no root/key/canonical serialized plaintext.

`VaultUnlockResult` rejects root/fingerprint access after close; status remains historical outcome information. `CreationResult` delegates root lifetime to it. Envelope/TLV scratch clear is not an API lifetime mechanism (O6). A few failed validation paths can leave newly allocated model/string/provider copies until GC; this is not proof of secure erasure, nor is such a guarantee claimed. Immutable credential lifetime must be addressed explicitly in API ownership decisions rather than promising that wiping the root wipes every known credential.

Normal exception paths clear owned root/key arrays. Fatal JVM errors or provider internals cannot be given a universal wipe guarantee. No cleanup exception path was found that changes a prior failed unsafe operation into reported success. No raw password/root/TOKEN plaintext/bootstrap bytes enter production exception messages or logs. F4 is the narrow secret-derived formatting exception.

## 10. Graph/fold assessment

`TokenGraph` was inspected independently of its test verdicts. Child-to-parent edges are built within each TOKEN_ID partition. Contradiction exclusion is global before partitioning. Exact duplicates collapse by canonical-model equality; metadata differences count as different canonical objects for defensive same-ID contradiction, but not as different TokenValues.

Both Kosaraju traversals are iterative. Nodes are marked when pushed, bounding each stack to V. The first traversal advances per-node edge cursors before descent; finishing order is filled once per vertex. The second follows reverse edges and assigns a component before pushing. Self-loops remain in one component. Canonical parent lists prevent repeated edges from one child. Marking the target of an inter-component child-parent edge historical is sufficient on the collapsed DAG: every noncurrent ancestor has an incoming inter-component edge. All members of remaining current components become heads; none is chosen as representative.

Presentation is deterministic: TOKEN_ID ordering uses unsigned bytes; fixed-width lowercase hex supplies equivalent ObjectId ordering; groups appear in first-member order, heads in object order, values in first-head order, unresolved references in child/parent order. Input ordering does not drive semantics. Collections preserve full head metadata, including every member of a current SCC.

SCC passes are O(V+E), with E <= 4V. Overall evaluation is expected O(V log V + E) with sorting and ordinary hash distribution, **not an unconditional linear worst-case claim**: chosen Java hash collisions can degrade map/set work (F2). Reverse adjacency and result projections have O(V+E) space. No repeated transitive-closure search or recursion was found. Integer stacks/counts are bounded by actual Java list sizes; practical heap limits arrive before useful near-int-limit operation.

Folding sorts/deduplicates its internal original set, builds four parents then carry plus up to three, and canonicalizes each stage. N <= 4 yields one ordinary object, including N=0. N>4 yields `ceil((N-1)/3)` for an ordinary selected frontier; each stage retains the same TOKEN_ID/value/metadata references and computes a real keyed ID. If a selected ID already equals an intermediate stage ID, set union can collapse that repeated parent without losing causal coverage. No event nonce or synthetic ID is introduced.

`TokenPublicationPlan` owns caller-input validation and entropy for new identities; `TokenFold` owns stage structure; `TokenPublisher` owns execution and rechecks root/ID binding. These responsibilities are complementary. Re-encoding at publication is a deliberate check and avoids retaining canonical plaintext. Direct internal fold input still silently deduplicates (O1); the production authorship boundary rejects duplicate supplied parents.

## 11. TOKEN observation/publication assessment

`DiscoverySource` freezes names/openers, not file contents or completeness. NIO lists only direct children, ignores noncanonical names/types, does not recurse into siblings, and checks regular-file type again before opening with no-follow. Root/namespace absence and unsafe type produce bounded classifications or IO failure. NIO enumeration failures preserve already collected candidates where practical. The full snapshot still costs memory proportional to all candidate names before parsing.

`BoundedObjectRead` allocates 1025 bytes and stops when full. Zero progress fails instead of spinning. `TokenStoreReader` composes exact-size envelope validation and exact TOKEN grammar, clears envelope/P buffers, closes channels/snapshot, retains independently valid objects, and reports structural reasons without provider exception text. A read-handle close failure after successful validation preserves that token and adds an unavailable diagnostic; it does not retroactively forge or revoke authentication. Unsupported/custom provider runtime exceptions are not uniformly normalized by this reader; provider capability qualification and error composition remain necessary.

Authorship accepts caller-selected parents, including unavailable IDs. It neither requires a graph nor asks whether conflicts/diagnostics permit publishing. TOTP consumes a credential rather than a “ready” graph state. No hidden operation permission, winner selection, confirmation token, tombstone prohibition, or global diagnostic gate was found.

Publication constructs the complete object before calling storage, rechecks each planned ObjectId, clears semantic plaintext even on failure, and stops at the first unacknowledged stage. Earlier immutable stages remain ordinary history. No rollback/delete and no second graph transaction exists. Retrying the **same immutable plan with the same root** is stable; rerunning `planNew` is a different new-token operation and is not the retry contract.

Exact-existing NIO success performs a bounded regular-file byte comparison with no semantic decrypt and no fresh file/directory barrier in the ordinary preexisting path. It still attempts `createDirectory` to establish/validate the namespace; an existing directory is not modified. A failed earlier namespace-creation barrier may be retried on the same instance, which is namespace durability work, not a fresh force of an exact existing object. Losing a concurrent no-replace link race may leave a staged file to clean, but never rewrites the winning target. F1 is the exception to correct canonical target selection.

Known durable acknowledgement yields NEW/EXACT. An exception after installation, force, or channel close remains conservatively unsuccessful/possibly ambiguous; no assumption of absence follows. This can lose success information, but cannot falsely manufacture success. F3 addresses future reporting, not a required automatic retry mechanism.

## 12. VAULT lifecycle assessment

### Create

Source order is absence observation/close, password validation, three independent entropy draws (root/salt/nonce), complete encoding, authenticated candidate/root validation, separate durable stage, exact staged-byte plus authenticated root validation, one no-replace install attempt, result creation, best-effort cleanup and local-array wiping. An observed malformed/unreadable/wrong-type canonical entry does not authorize overwrite. Neither objects-v1 emptiness nor TOKEN discovery is consulted. Initial installation remains no-replace even when an identical candidate appears concurrently.

Entropy/runtime crypto failures propagate as operational exceptions while finally clears allocated locals. Candidate validation and stage failures do not install. Backend install IO/capability failures return FAILED, including uncertain installed residue. Stage close is not a durability barrier and does not undo success. There is no side effect before password validation except canonical observation; no creation root is persisted before candidate validation/staging.

### Open

Open observes canonical only, reads at most 88 bytes, performs structural/password checks before the fixed-cost KDF, authenticates before returning the root, and returns an owned closeable copy. It requires no remembered fingerprint, TOKEN scan, or freshness evidence. Unsafe observed canonical types are unavailable. Wrong password and authenticated-wrapper damage cannot generally be distinguished and correctly share authentication failure. Literal lowercase resolution alone fails on case-insensitive aliases (F1).

### Password change — source order verified

```text
read BASE (84)
  -> authenticate current password (86–90), copy exact root, close unwrap result
  -> validate new password before entropy
  -> draw salt and nonce only (91–92)
  -> encode and authenticate candidate/root/fingerprint (93–94)
  -> durable separate stage (95)
  -> compare exact staged bytes and authenticate stage (96)
  -> read CURRENT as canonical regular bytes (97)
  -> CURRENT absent/unreadable: FAILED; unequal to BASE: STALE (99–101)
  -> one replacement attempt (103)
  -> SUCCESS only after backend acknowledgement (105)
  -> cleanup and wipe (109–111)
```

There is no new root draw, token rewrite, or storage mutation before authentication of current password. Same-root changed wrappers and different-root changed wrappers are both stale because exact BASE bytes, not fingerprints, are compared. Malformed-but-readable CURRENT differing from BASE is stale; absent/unreadable CURRENT cannot be compared and fails. Candidate/stage validation occurs before CURRENT observation, keeping expensive KDF work outside the compare-to-move window.

### Accepted compare/replace race

Another writer may change canonical after CURRENT equals BASE and before the atomic move. Both writers can succeed at different instants; the last replacement can win. The implementation explicitly says compare-before-replace, not CAS. Backend code adds one regular-file check immediately before move; there is no intervening KDF, stage write, or gratuitous directory force. Eliminating one redundant BASE-read type check would not close this race. A second comparison only moves the window. No cheap portable unconditional CAS was identified. Cross-process locking would need a cooperative store-wide contract and would not serialize arbitrary external synchronization. Do not restore generation counters, journals, or old security-memory machinery to solve an accepted r17 limitation.

## 13. NIO/filesystem/durability assessment

Staging uses same-directory temporary files, writes all bytes while checking progress, and forces the staged channel. TOKEN and initial VAULT installation use `Files.createLink`, preserving no-replace semantics; observed existing targets are never truncated to repair them. TOKEN additionally forces its open staging channel after the link and forces the containing directory. New object namespace creation requests root-directory force first. VAULT replacement closes the forced stage before atomic move, then requests root-directory force. Temporary files are ignored by discovery/canonical open and deleted best-effort; installed canonical paths are never removed during cleanup.

`ATOMIC_MOVE` makes handling of an existing target provider-specific, and other copy options do not strengthen its guarantees. The backend explicitly documents this and propagates failure without a non-atomic fallback. A moved symlink would be the link entry, not a write through to its referent; here the staged source is a created regular file and canonical is checked as regular. A target changing after that check remains a TOCTOU limitation under the trusted-local-execution baseline. [JDK `Files.move`](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Files.html#move(java.nio.file.Path,java.nio.file.Path,java.nio.file.CopyOption...)).

Hard links, atomic overwrite of an existing target, no-follow opens, and directory-channel force must be supported by the provider. Java NIO does not make every such backend universally suitable. Existing-name validation has the additional missing capability/guard in F1. Ordinary provider failure is conservative, but errors can be IO or unchecked unsupported-operation depending on the boundary.

Durability wording was audited in README, lifecycle/SPIs, `NioDurability`, `StorageDurability`, and NIO provider comments. It generally means successful acceptance of the required local operations, not power-loss testing or perpetual retention. `NioDurability` checks a directory, opens a read channel, requests `force(true)`, and wraps ordinary unsupported cases as IO failure. Its documentation explicitly disclaims universal directory-fsync guarantees; a provider silently offering weak force semantics cannot be detected merely from a successful call. Tests record barriers or perform accepted force and close/reopen; neither establishes universal physical persistence. No additional durability-overclaim finding is warranted.

### Concurrency and thread safety

| Scenario | Assessment |
| --- | --- |
| Two separate TOKEN publishers, same exact object | One link wins; other reads exact and may acknowledge; no overwrite |
| Different assertions | Different keyed names coexist; graph later describes concurrency |
| Different bytes at same supplied ID | Existing mismatched target remains untouched; publication fails |
| Two initial VAULT creators | One hard link wins; other fails, even if exact bytes coincide |
| Two rewraps | Intervening state before compare is stale; post-compare race accepted, no CAS guarantee |
| TOKEN publication during rewrap | Same root makes operations independent; rewrap does not change TOKEN namespace |
| Observation during publication | New staged names ignored; immutable canonical bytes validated when observed; set need not be complete |

No mutable static production state was found. Immutable domain values/plans/graph results can be shared subject to credential lifetime. Stateless codec/crypto operations use local JCA objects. `VaultUnlockResult` and `CreationResult` are stateful and not safe for concurrent close/use. `DiscoverySource.Snapshot` owns an optional thread-confined resource. NIO VAULT handles/stages are explicitly thread-confined; object publication handles also contain unsynchronized `closed/rootSyncPending` and should be documented as thread-confined. Separate handles/processes are the conceptual concurrency model, not concurrent calls on one stateful handle. Entropy and KDF injection also inherit the injected implementation's thread behavior. Future API documentation must state these ownership rules.

Resource tracing found try-with-resources around channels, streams, directory streams, and unlock results. Stage storage owns outstanding handles and closes them on store close. Normal/validation/IO failures attempt temp cleanup. Read/close secondary IO failures are conservative; Java suppression works for nested try-with-resources, although lifecycle result conversion deliberately drops exception detail. Cleanup failures can leave encrypted temp material, not a second authoritative bootstrap or object. This warrants later provider fault tests, not a claim of secure deletion.

## 14. API/visibility assessment

This is a **complete inventory of declared externally accessible production types and public members**, verified with `javap -public` and source. Standard inherited JDK `Object`/`Record`/`Enum` methods are not repeated per row; every enum also inherits `name`, `ordinal`, `compareTo`, `getDeclaringClass`, `describeConstable`, equality/hash/string behavior. All object types inherit the ordinary Object methods. Record-generated declared equality/hash/string/accessors are explicitly included below. There are no public protocol constants or public entropy/KDF types.

| Public production type | Public declared members | Classification |
| --- | --- | --- |
| `ObjectId` | static `fromFilename(String)`; `filename()`; `equals(Object)`; `hashCode()`; no public constructor | Public due module boundary; plausible future user value, not proof of authenticated content |
| `DiscoverySource` | `snapshot() throws IOException` | Intentional SPI |
| `DiscoverySource.Opener` | `open() throws IOException` | Intentional SPI detail; should not become general user workflow API |
| `DiscoverySource.Candidate` | constructor `(ObjectId, Opener)`; `id()`; `opener()`; `equals`, `hashCode`, overridden `toString` | Intentional SPI transport |
| `DiscoverySource.SnapshotIssue` | constants `NONE`, `ENUMERATION_UNAVAILABLE`, `UNSAFE_NAMESPACE`; static `values()`, `valueOf(String)` | Intentional SPI diagnostic |
| `DiscoverySource.Snapshot` | constructors `(List<Candidate>, SnapshotIssue)` and `(List<Candidate>, SnapshotIssue, Closeable)`; `candidates()`; `issue()`; `close() throws IOException` | Intentional SPI ownership mechanism, keep out of high-level user API |
| `V1ObjectPublicationStore` | `publish(ObjectId, byte[]) throws IOException`; `close() throws IOException` | Intentional SPI |
| `V1ObjectPublicationStore.PublicationResult` | constants `PUBLISHED_NEW`, `ALREADY_PRESENT_EXACT`; static `values()`, `valueOf(String)` | Intentional SPI acknowledgement |
| `VaultBootstrapStorage` | `openCanonicalRead() throws IOException`; `stageInitial(byte[]) throws IOException`; `close() throws IOException` | Intentional SPI; low-level bytes, not user lifecycle API |
| `VaultBootstrapStorage.StagedBootstrap` | `openRead()`; `installInitialDurably()`; `close()`; all throw IOException | Intentional SPI staging detail |
| `VaultBootstrapReplacementStorage` | `stageReplacement(byte[]) throws IOException`; inherits all bootstrap-storage members | Intentional optional replacement capability |
| `VaultBootstrapReplacementStorage.StagedReplacement` | `openRead()`; `replaceCanonicalDurably()`; `close()`; all throw IOException | Intentional SPI staging detail |
| `NioDiscoverySource` | constructor `(Path)`; `snapshot() throws IOException` | Likely future user/backend configuration entry point |
| `NioV1ObjectPublicationStore` | static `open(Path, StorageDurability) throws IOException`; `publish(ObjectId, byte[]) throws IOException`; `close()` | Likely backend configuration entry point; low-level operations remain SPI |
| `NioVaultBootstrapStorage` | static `open(Path, StorageDurability) throws IOException`; `openCanonicalRead()`; `stageInitial(byte[])`; `stageReplacement(byte[])` (IO); `close()` | Likely backend configuration entry point; lifecycle should be composed elsewhere |
| `NioDurability` | implicit public no-arg constructor; `syncDirectory(Path) throws IOException` | Intentional provider capability implementation |
| `StorageDurability` | `syncDirectory(Path) throws IOException` | Intentional injectable SPI; trusted durability assertion |

Total: **17 accessible types including nested types**. No type was found public merely to expose entropy, mutable key internals, a graph DB, or fault injection. NIO test-fixture fault classes are test artifacts, not production surface. Java access across the two modules explains the SPIs and ObjectId; public here does not mean a promised stable general-purpose API.

The separate initial/replacement stages prevent conflating no-replace and replacement operations. Combining them solely to save lines would erase useful capability distinctions. Their repeated `openRead/close` is not expensive abstraction duplication. Conversely, `VaultUnlockResult` currently combines concepts that should be separated before exposure (F3).

`VaultLifecycle`, `TokenStoreReader`, `TokenGraph`, `TokenPublicationPlan`, and `TokenPublisher` should be composed behind user capabilities, not all promoted to public. `ValidatedToken` should remain a trusted internal fact boundary: its constructor checks non-null/model shape, not authentication. Envelope results, byte cursors/TLV types, folds/stages, raw key helpers, KDF/entropy seams, and NIO fault operations should stay hidden. Public DTO/value choices must preserve exact metadata and truthful state without exposing these orchestration mechanics.

## 15. Module/test-layering assessment

Production direction is **storage-nio -> core** (`api(project(":core"))`). Core has no NIO implementation dependency. BC is core implementation/runtime, not exported source API. No production cycle exists.

The reverse **core testImplementation -> storage-nio main and test fixtures** is real but acyclic at source/task level: NIO production depends on core main, not core tests. Its stated and actual purpose is exercising package-private `dev.totipo.format` orchestration against real adapters. Fault fixtures in `storage-nio/src/testFixtures` can reach NIO package-private seams. Some storage-nio tests also use `dev.totipo.format` to reach core package-private internals on the classpath; there is no JPMS descriptor enforcing package exports here.

This is acceptable temporary test organization, with maintenance cost rather than a correctness finding. Moving integration tests under storage-nio today would also require rehoming shared helpers/corpus access or widening visibility. Once a user composition boundary exists, cross-module black-box tests should live with the backend or a dedicated integration suite, and the special reverse edge can shrink. Avoid freezing internal signatures to satisfy current tests.

## 16. Resource/DoS assessment

Each object read/allocation is bounded, semantic fields are bounded before allocation, parents are capped at four, and VAULT reads are capped at 88. No hostile TLV length causes an unbounded allocation through the production TOKEN path. Password KDF memory/work parameters cannot be selected by a malformed header.

Whole-store resources are not bounded: NIO collects candidate paths/openers, Snapshot copies/sorts them and builds a duplicate set, observation accumulates valid models and diagnostics, and graph builds indexes/adjacency/SCC arrays/projections. Validated objects, unresolved edges, and frontier size can all be large. Diagnostics add one ordinary record per failing candidate (occasionally another for close failure), not attacker-sized raw exception text; memory is O(candidate count), not an extra multiplicative expansion. Snapshot issue records are small. Reporting all of them is optional implementation design, not unavoidable protocol memory.

F2 is an avoidable superlinear pre-authentication cost. Repeated hex formatting in sort comparators creates many small allocations but does not independently make sorting quadratic. Current graph hashing has expected, not universal, linear lookup cost. No combinatorial merge or unbounded recursion was found.

Later application controls should allow budgets/cancellation, incremental processing, and diagnostic aggregation while returning the validated subset with truthful incompleteness diagnostics. They must not silently classify omitted parents as absent history, erase independently validated facts, or install a global operation gate. Do not invent a protocol-wide maximum store size. Concurrency limits around Argon2 work are also an application resource choice, not different KDF parameters.

## 17. Test/conformance evidence assessment

### What 90/90 actually executes

`Phase2ConformanceTest.everyImplementedCaseExecutesWithoutSkipping` derives cases from the manifest, dispatches to real consumers, and only adds an ID to `executed` after its assertions return. It checks implemented/deferred categories, full ID-set equality, 90 total, and exact category counts. A failed assertion cannot be recorded as a consumed passing case. IDs in category sanity checks are inventories, not production behavior selectors.

| Category | Count | Production evidence / limits |
| --- | ---: | --- |
| bootstrap | 4 | Real BC KDF and unlock; exact key/root/header/fingerprint, strict char conversion, independent fixture encryption; writer checked additionally in bootstrap-writer tests |
| crypto | 5 | Real envelope open/seal/key hierarchy and exact intermediates; post-AEAD malformed plaintext authenticated independently before strict rejection |
| encoding | 30 | Genuine authenticated envelopes over valid/invalid P; exact production grammar, semantic fields, canonical re-encode and envelope comparison for valid cases |
| metadata | 7 | Exact presence/value through production model/codec, including empty/zero/u64-max |
| size | 1 | Maximum legal 1005-byte semantic TOKEN with four parents |
| graph | 13 | Production evaluator on explicitly symbolic validated facts; full heads/objects/values/unresolved/conflict assertions |
| fold | 6 | Production stages; symbolic preceding-stage IDs replaced by actual keyed IDs; real sealing/opening and final graph coverage |
| storage | 13 | NIO materialized observations and publication; injected unreadability/ambiguous residue; exact bytes and graph consequences |
| totp | 3 | All six RFC rows for each algorithm, exact counters/counter bytes/codes |
| vault | 8 | Production lifecycle and real crypto using controlled SPI storage outcomes; abstract labels lifted into real wrappers preserving BASE equality |

Graph cycles and same-ID contradictions are explicitly symbolic, not assertions of constructible HMAC collisions. Fold original frontier facts are symbolic in the corpus consumer; separate integration tests construct real original objects. This is legitimate layering, not fabricated cryptographic evidence.

Storage observation vectors with repeated paths are materialized separately per observed entry, then classifications are combined. This checks interpretation of an observation sequence; it does not prove simultaneous directory snapshot consistency. Valid expected tokens in that consumer are partly reconstructed through the same production parser, so independent field/byte checks in the codec corpus remain important. Ambiguous storage outcomes use fakes for both installed/not-installed possibilities and additional NIO fault tests for real residual state.

VAULT workflow byte labels are abstract by the corpus contract. The consumer derives deterministic wrappers so exact equality remains meaningful, runs production lifecycle, checks attempt counts and residue, and rejects unknown workflow fields. Its local orphan-array equality check alone is weak: that array is not connected to the store. The stronger evidence is the narrow bootstrap SPI and `VaultNioWorkflowTest`'s real orphan files before/after creation. No physical durability claim should be based on the local-array assertion.

Graph/fold/storage/vault consumers check exact allowed field shapes; unsupported fixture shapes fail. Byte/bootstrap/TOTP consumers assert current semantic and expected crypto fields but do not uniformly reject additional unknown fields or validate the complete JSON schema. Descriptive `notes/source/operation` information is not always an assertion. With immutable current hashes, no relevant current expected result was found silently omitted; on a future repin a newly added expectation could be ignored by those consumers. Unify strict consumer-shape checks as later corpus maintenance, not a reason to reject today's 90/90 count. The post-AEAD consumer's strict-reader checks are also exercised through real `TokenStoreReaderTest` invalid-storage checks.

No ID-specific production behavior teaches Java vector answers. Workflow consumers branch on operation/kind/durability fields and check outputs; graph symbols map injectively to complete values and IDs. Fast test KDFs occur only in explicitly marked fault/ownership tests; real BC is exercised in corpus and NIO workflows. In-memory fake durability is labeled separately from real accepted forces.

### Test quality and gaps

Strong existing evidence includes same-root/different-root stale rewrap, malformed and wrong-length staged bytes, no entropy before authentication, injected entropy failure wiping, read/write bounds and nonprogress, no-replace races, unsupported atomic move, ambiguous installation residues, exact retry, late parents/cycles/disappearance, all seven whole-value conflict fields, metadata permutations, collection immutability, and 20,000-node iterative chain/cycle tests.

Reflection-based owned-array wipe assertions and field-layout assertions intentionally couple some tests to internals; they do not substitute for behavioral evidence. Existing permutation tests compare production outputs across orderings, supplemented by explicit expected graphs; they are not an independent general SCC oracle. Some fault seams fail before an OS call rather than simulate kernel crash behavior. File-channel close failure and temp-cleanup failure in the concrete provider are not exhaustively injected, although higher-level close/error behavior is tested. F1, F2 and F6 identify actual gaps. No time sleeps, current-clock assertions, or random expected outputs were found; synchronization tests use barriers with timeouts.

### High-value properties to add later

1. Generate bounded TOKEN tuples and invalid TLV edits: canonical write/read/write identity, strict rejection, and exact optional metadata. Existing hand-picked round trips do not cover all combinations.
2. Compare small generated symbolic graphs with an independent reachability/SCC oracle, including contradictory IDs, partitions, removals and reappearances. Existing ordering tests alone cannot establish evaluator correctness.
3. Exercise generated wide frontiers and failure positions/residues: final causal coverage, per-stage value/metadata preservation, and immutable-plan retry byte identity. Include an original ID equal to an already constructed intermediate.
4. Generate rewrap schedules around stage/CURRENT/move, verifying root/fingerprint invariance and explicit uncertainty after acknowledgement failures. Include the accepted post-compare race, not an expected CAS guarantee.

Fuzz entry points: strict password/bootstrap preflight, `TokenReader`/TLV truncation/order/widths, envelope shape plus authenticated malformed interiors, bounded-read nonprogress/close behavior, and symbolic graph structures. Random GCM ciphertext alone mostly tests tag rejection; construct authenticated malformed padded plaintext to reach deeper validation. Start with deterministic Java/JUnit generators and replayable seeds; consider a managed fuzz harness only after measuring value. No fuzz dependency was added.

## 18. Dead/redundant code and minimality assessment

Call-site searches confirm `CryptoSupport.sha256` has no production caller; only test fixture/fault helpers use it. `ByteCursor.u32be`, `u64be`, and `position` likewise have only test call sites. These are genuine candidates to move to test helpers/remove when simplifying, not necessary runtime protocol operations. Their presence is localized and not security-sensitive enough to merit a separate finding. Do not infer that all currently test-invoked top-level orchestration is dead: the public composition layer is deliberately not built yet. The char-password unlock overload and TOTP entry points are useful implementation capabilities awaiting that layer.

No active DEVICE, signatures/provenance, VAULT_BINDING, READY/PROCESSING_INCOMPLETE, candidate permission, confirmation token, generation counter, event nonce, security-memory journal, persistent graph database, mandatory cache, or rollback database was found. Matches in vendored historical specification text and old report link names are not active machinery.

`CryptoSupport` and TOTP implement different HMAC contexts, not duplicate crypto. `NioFiles` centralizes small shared mechanics; `NioDurability` isolates a real capability; split stage interfaces express meaningful differences. `VaultLifecycle.validates` compares both exact recovered root and derived fingerprint; the latter is logically redundant after equal roots but low-cost relative to the deliberate authentication checks. It does not substitute for exact wrapper comparison. No wholesale class merging is recommended to reduce line count.

## 19. README/security-claim assessment

README correctly distinguishes corpus completion from stable public API, desktop/Android readiness, and independent security review. It scopes configured-store observation to the valid observed subset, says exact metadata is preserved, describes explicit retries, says local acknowledgement is not remote propagation, identifies the remaining compare-before-replace race, and disclaims rollback protection and universal power-loss proof.

F1 qualifies its “only lowercase vault” and namespace wording on aliased providers; F5 addresses stale/broken evidence; F6 qualifies build portability. README should explicitly say independent interoperability has not yet been demonstrated rather than leave readers to infer it from portable-corpus success.

The trusted computing base is the JVM/JCA providers, BC Argon2id, CSPRNG, core validation/orchestration, configured backend and durability capability, and trusted local OS/kernel/filesystem/process namespace. Observed external-store bytes/names are hostile; completeness/freshness is never certified. Malicious same-UID syscall racing is outside baseline, but ordinary case-insensitive lookup is inside it and cannot dismiss F1.

No claim equating authentication, fingerprint, or content address with freshest history was found. Exact BASE comparison establishes only this operation's observation relationship. Retained old wrappers remain usable with old passwords. Validated graph results are relative to supplied facts; their deterministic order does not establish a newest/winning assertion. `SECURITY.md` is appropriately brief, prerelease-scoped, and directs vulnerability reports privately; no disclosure message was sent during review.

## 20. Recommended remediation ordering

### Before current implementation commit / next acceptance

Only **F1**: fix or explicitly exclude aliased provider naming behavior and add the regression. Phase 5 is already committed; this recommendation means a corrective follow-up before approving it as an unrestricted r17 NIO implementation. Do not rewrite history or implement changes as part of this report.

### Before public API freeze

Resolve **F2** with the small sorted-adjacent duplicate check and robustness regression. Resolve **F3** before application callers depend on ambiguous `FAILED` or a storage-bearing crypto result. Address **F4/F5** while the changes are cheap. Make explicit decisions about session/credential retention, thread confinement, trusted SPI capability exposure, and which observed state is user-facing. Plan migration of reverse-edge integration tests around the actual public composition boundary; it is not a reason to widen internals now.

### Later hardening / before desktop or Android support

Address **F6** and qualify target providers, including actual case-insensitive filesystems, no-follow behavior, hard links, atomic existing-target replacement, and directory force. Add broader crash/fault tests, resource budgets/cancellation/diagnostic aggregation, generated properties and focused fuzzing, and independent interoperability. Confirm Java 17 execution as well as bytecode compatibility on intended runtimes; the current tests execute under JDK 25. None of this calls for native code, new protocol limits, persistent journals, or a graph DB as a default.

## 21. Public-API design inputs

Likely user-facing capabilities are open/create vault, observe/list relative current token state with diagnostics, compute TOTP from an explicitly selected complete value, create/update/delete/restore complete token assertions, resolve selected conflicts through ordinary assertions, change password, and close a session with precise best-effort ownership guarantees.

These are capabilities, not proposed signatures. The API must preserve all head objects and their exact metadata, whole-state alternatives, tombstone labeling, unresolved references, and the difference between local acknowledgement and historical freshness. It should not claim an inventory is exhaustive merely because no diagnostics were returned, or gate known credential use on global discovery completeness. Explicit retries must reuse the same authored assertion/plan. A new-token action must still draw a fresh identity.

Keep internal graph algorithms, validated-fact construction, folds/stages, envelope/parser results, keys, KDF/entropy seams, and NIO fault operations hidden. Compose `VaultLifecycle`, `TokenStoreReader`, `TokenGraph`, `TokenPublicationPlan`, and `TokenPublisher`; do not simply publish all their current methods. Separate stable user concepts from low-level backend SPIs. Make close/credential-copy semantics and lifecycle failure certainty design inputs before signatures are frozen.

## 22. Validation evidence and final answers

### Commands and provenance

Required baseline commands were run, including both runtime dependency reports, Java 17 bytecode verification, focused snapshot/profile tests, and checksum verification. The isolated offline full run passed with 252 core plus 45 storage-nio tests. The inventory test executed all 90 assertions groups before counting them. BC 1.86 is strictly locked and verification metadata pins its JAR/POM hashes; Jackson 2.18.2 and JUnit 6.1.3 are test-only. Gradle wrapper distribution has a pinned SHA-256; initial availability required a wrapper download. Offline operation succeeded once artifacts were available. Normal builds did not regenerate the specification.

Temporary review probes and logs were written only under `/tmp`. They exercised unchanged classes for case-insensitive provider behavior, hostile filename hashes, and direct secret-container formatting. The provider probe does not replace actual target-platform qualification. No production/test files or dependencies were added for these probes.

Before the first build, every file under `core/src` and `storage-nio/src` was hashed into a sorted manifest. That starting manifest's SHA-256 was:

```text
8629bddbca8721d5322631ddbe195b4ce4a3a42cb98a4e6006a0602d45ae8d11
```

### Final report-only validation

The required final `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test` passed: **297 tests, 0 failures, 0 errors, 0 skips**. `git diff --check` passed. Snapshot integrity passed again for **97/97 imported files**. All **189 files under the two modules' src trees** passed comparison with the starting hashes; regenerating the sorted manifest and comparing it byte-for-byte also found no additions, removals, or changes. Production and test source hashes are unchanged.

The wrapper JAR SHA-256 also matches the bootstrap script's pin: `238e777fcddd7e34f9708186085def2abd6e08e658505b38718d79d74c21abd5`. No existing tracked file changed. The final tracked `git diff --stat` is empty because the only addition is untracked:

```text
$ git status --short
?? R17_IMPLEMENTATION_ADVERSARIAL_REVIEW.md
$ git diff --stat
(no output)
```

### Suspected-area disposition

| Hypothesis | Disposition |
| --- | --- |
| A — UnlockResult responsibility mixing | Confirmed API debt, F3; not an authentication bypass |
| B — reverse test dependency | Confirmed test-only edge, acceptable temporary organization, O2 |
| C — replacement race | Accepted r17 compare-before-replace, correctly ordered and honestly described |
| D — public SPI surface | All current exposed storage capabilities have cross-module uses; keep them distinct from the future user API |
| E — entropy visibility | Dismissed: package-private, with SecureRandom default |
| F — close/cleanup failures | No failure-to-success conversion found; conservative IO ambiguity and best-effort non-gating stage cleanup are intentional |
| G — error taxonomy | Current safety conservative; application distinctions insufficient to freeze, F3 |
| H — exact-existing semantics | Read-only bounded comparison with no ordinary fresh force/decrypt; canonical-name defect F1 remains |
| I — diagnostic growth | Unbounded linear record count, no raw-message amplification; later budgets/aggregation useful; F2 is a separate CPU amplification |
| J — generated secret methods | Containing models redact; direct SecurityBytes content-hash string leak confirmed, F4; internal array-record equality is not used as semantic equality |

### Direct answers

1. **Does the current implementation faithfully implement r17?** The crypto/codec/graph/fold/lifecycle paths reviewed agree with r17 on the tested case-sensitive store. **Not without qualification across accepted NIO providers: F1 violates canonical-name semantics.** Fix or reject that provider behavior; no broader protocol rewrite is indicated.
2. **Is the 90/90 portable-conformance claim supported?** **Yes**, as execution of the exact pinned language-neutral corpus through production consumers. It is not comprehensive cross-provider, physical-crash, or independent interoperability proof.
3. **Is there any finding that should block committing Phase 5?** **Yes, F1**, for unqualified approval of the current provider surface. Phase 5 was already committed at review start; no commit/revert was made here.
4. **Is there any finding that must be fixed before public API design?** **F1 must be resolved; F3's responsibilities/certainty and credential lifetime must be settled before API decisions become commitments.** F2 should be repaired in the preparatory remediation pass. API exploration can use this report, but freezing the present internal results would carry avoidable debt.
5. **Is the current core/storage-nio layering appropriate?** **Yes in production.** The reverse test dependency is acceptable temporary integration organization, to revisit when the public composition boundary exists.
6. **Are secret ownership and cleanup rules coherent?** **Mostly yes for synchronous operations and owned root results.** F4 needs a small redaction fix. Retained credential models are immutable, not wipeable; root close must not be advertised as complete session-secret erasure. JVM/provider copies limit any erasure claim.
7. **Are durability/freshness claims appropriately scoped?** **Generally yes.** Provider-accepted barriers, local acknowledgement, no universal power-loss proof, no freshness/rollback guarantee, and the residual compare/replace race are stated honestly. Canonical-name portability needs F1's correction.
8. **What should the next milestone be?** **A focused remediation/provider-qualification pass, then public-API design informed by outcome certainty, lifetime ownership, truthful state presentation, and hidden internal composition.** Do not add features or redesign r17 to address these findings.
