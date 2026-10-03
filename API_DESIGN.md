# Totipo Java application API

This document is normative for this implementation phase, not part of the Totipo
wire-format specification. The pinned v1/r18 specification and unchanged corpus
remain authoritative for protocol facts. `org.totipo` defines library API behavior
for applications; `org.totipo.storage.nio.NioTotipo` is the ordinary filesystem entry point. There is
no API stability promise yet.

## Maven modules

`totipo-core` contains the portable protocol/application API and core implementation.
`totipo-storage-nio` supplies the normal filesystem/NIO entry point and storage
provider, exposing core transitively. Ordinary applications use `NioTotipo` and
the high-level API; publication does not promote experimental SPI internals to
normal application entry points. See README for release availability and coordinates.

## Entry points and lifecycle outcomes

`NioTotipo.open(path, password)` opens an existing configured-store directory and
returns `OpenResult`: `Opened(session)`, `Absent`, `Unavailable`, `InvalidVault`,
or `AuthenticationFailed`. Opening is read-only. Authentication failure is not a
claim that the password is wrong: authenticated bytes may have been corrupted or
replaced. Invalid Java password input (malformed UTF-16 or more than 1024 UTF-8
bytes) is a programmer error. Password characters remain caller-owned.

`NioTotipo.create(path, password)` requires an existing directory and returns
`CreateVaultResult`: `Created(session)`, `AlreadyExists`, `Failed`, or `Uncertain`.
Presence observed before installation yields `AlreadyExists`. Failure after entry
to the no-replace installation boundary is conservatively `Uncertain`, including
a concurrent creator winning that race. Never blindly retry uncertain creation;
reobserve/open the canonical vault.

`session.changePassword(currentPassword, newPassword)` returns
`PasswordChangeResult`: `CHANGED`, `AUTHENTICATION_FAILED`, `STALE`, `FAILED`, or
`UNCERTAIN`. `STALE` includes a changed authenticated root or changed canonical
BASE before replacement. An unavailable/invalid observation or definite staging
failure is `FAILED`. Once replacement is attempted, unacknowledged replacement
is `UNCERTAIN`; neither password is then asserted to be canonical. Recover by
re-observation/reopen. There is no automatic retry or rollback. Rewrapping retains
the existing root, draws fresh salt and nonce, and does not rewrite TOKENs.
Historical wrappers and their old passwords remain usable; this does not rotate the
root, revoke old wrappers, provide rollback protection, or recover from root
compromise. Compare-before-replace is not CAS.

The pinned protocol VAULT record is exactly **87 bytes**. Lifecycle reads of
password-change BASE/CURRENT and staged creation/replacement records request at
most `VaultBootstrap.RECORD_BYTES + 1` bytes (88 including lookahead), accepting
only an exact-length record. Short/trailing data is an unusable observation and
causes definite failure before installation/replacement. Null preserves absence.
On the immediate CURRENT reread, absence or unreadability is `FAILED`; a present
exact-length record different from BASE is `STALE`; only byte-for-byte equality
permits replacement. No compare-to-replace race is removed by this check.

NIO open remains read-only even when the valid store has no `objects-v1` directory.
Publication-store construction validates the existing root only; namespace
creation and durability work occur on publication, not on open or initial scan.

These outcomes separate observation, authentication and persistence knowledge;
they do not expose the older internal mixed lifecycle result model.

## Session and state ownership

`VaultSession` is the live capability. It owns the root, decrypted TOKEN values,
configured-store resources, retained history references, builders and observation
machinery. `fingerprint()` belongs to the session alone. A fingerprint recognizes
a root; it proves neither authorization nor freshness.

`state()` is an immediate read of the latest emitted immutable `VaultState`.
There is always a state, initially `ObservationProgress.Enumerating(0)`. This
implementation reads a bounded observation and emits `Finished(processed,
hasDiagnostics)`; the progress model also permits `Processing` without invented
percentages. Finished means only that this local pass ended, including a pass
with diagnostics. It does not establish complete history, freshest history,
remote synchronization or rollback resistance.

States and descriptive projections contain no raw secret arrays, open file
handles, snapshots, storage SPIs or mutable graph objects. Alternatives carry
opaque session-local value references; the session resolves them for crypto and
materialization. Immutable private causal facts support historical merge bases.
Secrets are not copied into every emitted state. The session retains observed
unique values until close because arbitrary historical references remain valid.
This can grow with observed history. Secret wiping is best effort on the JVM.

Each emitted state has an internal monotonically increasing session-local
sequence, never exposed publicly. Observation/emission is serialized; stale work
cannot replace a newer emission. The sequence is not a protocol generation,
freshness proof, global version or operation validity token. A larger sequence
never invalidates an operation or reference.

Old states remain descriptively readable after newer emissions and after close.
Heads and alternatives are session-scoped, not state-restricted. Receiving states
accept references from any state of the same session, even if the value/head is
no longer current. References from another session are programmer errors, even
when the sessions opened the same root.

## Replay-latest stream

`states()` is a `Flow.Publisher<VaultState>` with independent subscription demand.
`onSubscribe` comes first. After positive demand, the first state delivered is
the latest known state at delivery (at least as new as at the demand request).
Later deliveries have strictly increasing hidden sequence numbers. Subscribers
with zero demand retain only the latest available state; there is no unbounded
per-state queue. Demand saturates at `Long.MAX_VALUE`. Nonpositive demand signals
`onError` for that subscriber. Subscriber callback failures cancel that subscriber.

Callbacks are serialized per subscription and dispatched on the common pool;
application callbacks hold neither the provider gate, local secret/lifecycle lock,
nor publisher monitor.
Ordinary storage failures emit diagnostics rather than terminating the publisher.
Close completes subscribers regardless of demand, after any callback already
in progress. There is no `onNext` after a terminal signal. A subscriber joining a
normally closed session gets `onSubscribe` then completion. Fatal observation
machinery failure, whether during refresh or merge prepublication observation,
closes the unusable session and signals `onError(cause)`, including to late
subscribers. Explicit close signals `onComplete`. The first lifecycle termination
to acquire the local lifecycle lock chooses an immutable terminal cause: a racing
later close/failure cannot replace it. Subscriber-specific invalid demand remains
an error for that subscriber; cancellation abandons its delivery. Demand after
session termination cannot change the selected terminal signal.

`close()` is safe inside `onNext`: it does not wait for subscriber callbacks,
including its caller's callback. Once that callback returns, its serialized drain
delivers the terminal signal exactly once, with no later onNext. Close can still
wait for an unrelated in-flight provider operation to establish persistence
certainty; providers never wait for subscriber callbacks as part of this facade.

Use a real `Flow.Subscriber`; it is not a functional interface:

```java
session.states().subscribe(new Flow.Subscriber<VaultState>() {
    public void onSubscribe(Flow.Subscription subscription) {
        subscription.request(Long.MAX_VALUE);
    }
    public void onNext(VaultState state) { render(state); }
    public void onError(Throwable error) { showFailure(error); }
    public void onComplete() { showClosed(); }
});
```

`requestRefresh()` is non-blocking. It requests another local pass; concurrent
requests can coalesce. No polling loop or remote sync is implied.

## Token projections and equality disclosure

`TokenState` exposes a logical `TokenId`, distinct complete semantic alternatives,
exact causal heads, unresolved references and field competition. `hasConflict()`
means more than one complete semantic value, not merely multiple equal heads.
If heads A and B carry X and C carries Y, alternatives are X with A/B and Y with C;
all three heads remain visible. Applications need not reconstruct grouping.

`TokenAlternative` exposes its non-secret `TokenDescriptor` and immutable heads.
The descriptor contains status, issuer, account, algorithm, digits and period.
`TokenHead` exposes token identity, `RevisionId` and exact `ClientMetadata`.
Client time uses optional unsigned-u64 raw long bits, with no freshness policy.
Metadata is outside semantic value equality. An absent client name differs from a
present empty name; exact validated Unicode text is retained without normalization.
Absent client time differs from zero. All unsigned values are retained as raw long
bits (for example, `-1L` is unsigned 18446744073709551615); use unsigned conversion
for display. Each equal-valued head retains its own metadata, including captured
heads that become historical. Tombstones remain complete values, including secrets;
tombstoning or deleting a token does not securely erase immutable history or provider
copies.

Head equality/hash identity is **session identity + TokenId + exact RevisionId**.
Alternative equality/hash identity is **session identity + TokenId + complete
semantic TokenValue**, including the secret internally. Captured head lists,
originating state, metadata and observation progress do not affect alternative
identity. Canonical opaque value keys in the owning session implement this without
exposing secrets or deriving equality from visible descriptors. Equal projections
have equal hash codes across emissions and after close, so UI selections work in
sets/maps even when equal-valued current heads change. Different sessions are not
equal/interchangeable capabilities even for the same underlying vault data.

`TokenCompetition` groups every non-secret field value together with the
alternatives carrying it. `CompetingSecret` contains descriptive `SecretGroup`s.
**Intentional disclosure:** secret bytes participate in complete TokenValue
equality. The model therefore reveals whether alternatives share a secret,
which alternatives share it, and the number of secret equality classes. It does
not reveal the bytes. `SecretGroup` is descriptive, not a mutation capability.

## Editing and deterministic causal bases

`CreateToken`, `UpdateToken` and `MergeToken` are distinct closeable builders.
`TokenEditor<T>` shares fluent setters only. Builders are not thread-safe.
Creation defaults to active status, empty issuer/account, SHA1, six digits and
30 seconds; a secret is required. Update pre-fills the selected complete value.
Metadata defaults to absent and may be explicitly supplied.

* `state.update(head)` uses exactly that one head as parent.
* `state.update(alternative)` uses exactly all equal-valued current heads for
  that token **in the receiving state**, if any exist. Otherwise it uses exactly
  the supplied alternative's captured immutable heads. Equality includes secret,
  status and every credential field. It does not use the session's later state.
* `state.merge(tokenId)` selects the receiving state's complete current frontier.
* `state.merge(alternatives)` selects exactly the union of supplied alternatives'
  captured heads, including historical or partial selections. Inputs must be
  nonempty, from one session and one token. Duplicate selected heads are set-unioned.

There is deliberately no `merge(TokenState)` overload. Ordinary updates never
perform the merge-only new-information gate and never silently add concurrent
parents. Existing fold planning handles parent sets exceeding the wire limit.

Merge pre-fills agreed fields, leaves disagreeing fields unresolved, and exposes
`unresolvedFields()` plus the selected inputs' competition. Any field can be
explicitly set to a new value; there is no automatic winner and no requirement
that the result equal an existing alternative. Callers may provide `NewSecret`
or select a `MergeSecretChoice` issued by that exact merge builder. Choices from
another merge are rejected even in the same session. State-level secret groups
cannot be passed as merge choices. Unresolved save returns definite `Failed`.

`NewSecret.copyOf(bytes)` defensively copies caller ingress, has a redacted
`toString`, and wipes its owned copy on close. Its `copy()` supplies an owned copy
of that caller-provided input only; callers using it must wipe their copy.
Builders copy ingress synchronously and do not depend on wrapper lifetime.
There is no existing-vault-secret export API, Base32 parser or QR import API.

## Merge freshness and partial resolution

A merge captures **M**, its selected heads, and **F0**, the entire current token
frontier of its receiving state. M may be a strict subset of F0. Before normal
save, the session performs a fresh observation and derives **F1**. A head in F1
is newly relevant if it is not causally contained by F0. Containment includes
F0 itself and transitively reachable parents, using original known causal facts
and newly resolved same-token ancestry. Merely learning an ancestor already
incorporated by an F0 head is not additional conflict. A newly visible current
head outside that containment is additional conflict. So are descendants
advancing beyond F0 and concurrent heads with an already-known semantic value.
Semantic equality does not erase causal relevance. Heads already in F0 but
intentionally omitted from M are not new.

Unavailable enumeration, unsafe namespace, or unavailable candidate reads make
the prepublication check insufficient: publish nothing and return
`Failed(OBSERVATION_UNAVAILABLE)`. Invalid authenticated/encoded candidates remain
diagnostic rejected inputs, not valid heads. Other tokens do not create semantic
additional conflict. Unavailable reads are conservatively gating because their
token relevance cannot be established.

If new relevant information exists, publish nothing and return
`AdditionalConflict(latest, resolution)`. The builder is terminal; its resolution
is frozen and not rebased. The application can close/discard the handle and start
a new merge, or call the independent `PartialResolution.save()`. That call
publishes exactly original M/value/metadata/fold stages with no further semantic
gate. It never returns AdditionalConflict, even if more heads arrive. It survives
builder closure. The successful check accepts a compare/check-to-publication
race: a concurrent head may appear immediately afterward. This is not CAS.

## Persistence knowledge and handles

These meanings apply to the **entire frozen operation**, not just its last I/O:

* **Failed:** Totipo knows this operation did not reach a potentially successful
  persistence point. Unresolved fields, failed preparation and unavailable merge
  observation are examples. The builder remains editable where appropriate.
* **PublicationUncertain:** the frozen operation may already have persisted.
  Later failed retries cannot remove that uncertainty.
* **Saved:** Totipo positively established successful configured-store durable
  installation of every required immutable object for this frozen operation.

Saved does not mean remote sync, universal physical power-loss survival, conflict
elimination, globally newest state, or observation by any peer. The NIO facade
requires the existing file/directory force capability. On an exact-existing
acknowledgement it additionally forces the file, object directory and root so an
uncertain earlier install is not treated as freshly durable solely from a read.
The low-level r18 exact-existing publication behavior remains unchanged.

Before the first provider publication call, the operation freezes token ID,
parents, complete value, metadata, fold stages, identities and exact encrypted
bytes. Builder setters are forbidden after Saved or PublicationUncertain. The
builder's secret override can then be wiped: retries retain ciphertext stages,
not decrypted values or a semantic recipe. Prepublication failure may leave a
builder editable. AdditionalConflict also makes its builder terminal.

Publication errors after entering the existing provider `publish` boundary are
conservatively uncertain: that SPI cannot distinguish a provider's pre-write
failure from a lost acknowledgement. Once uncertainty exists, only complete
acknowledgement can establish Saved. `PublicationRetry.retryPublication()` never
reobserves or rebases semantics and reproduces all frozen bytes and identities.

Retry and partial handles are independent of builders and registered with the
session. Each retry call transfers capability to the next result: a new uncertain
result owns a new independent retry handle; the previous handle is consumed.
Success consumes it. Closing an already consumed handle cannot close its
successor. Partial save likewise transfers capability on uncertainty and consumes
it on success. Closing a live handle abandons the operation and releases retained
ciphertext stages. Session close invalidates all handles. There is no automatic
publication retry.

The result types deliberately exclude impossible variants at compile time:

* Builder save returns `SaveResult`: Saved, AdditionalConflict, Failed or
  PublicationUncertain (AdditionalConflict remains merge-only).
* `PartialResolution.save()` returns sealed `PartialSaveResult`: Saved, Failed or
  PublicationUncertain, never AdditionalConflict.
* `PublicationRetry.retryPublication()` returns sealed `RetryResult`: Saved or
  PublicationUncertain, never Failed or AdditionalConflict.

`RetryResult` extends `PartialSaveResult`, which extends `SaveResult`. The same
`SaveResult.Saved`, `.Failed` and `.PublicationUncertain` records implement these
narrower interfaces, preserving shared handling without wrapper conversions or
duplicate outcome records. Retry publication uses a path whose return type cannot
construct a definite failure; it does not cast a general save result down.

## Blocking, threading and close

Open/create, all builder `save` methods, partial save, retry, password change and
session close may block for KDF, configured-store I/O or coordination. They are
inappropriate for Swing EDT or Android main thread.

Synchronization is split into a provider gate and a local secret/lifecycle lock.
The provider gate serializes scans, saves, retries, password change and provider
cleanup. Provider reads/writes and KDF run without the local lock. The local lock
protects canonical value maps, builder ingress overrides, ownership registration,
local materialization/TOTP and the transition to closing. Post-read projection
and interning also use this lock; graph evaluation occurs outside it. Builder
setters, factories and TOTP acquire only the local lock, so an unrelated blocked
provider scan or publication does not hold them up. This is not a real-time
latency guarantee: local CPU work, projection size, crypto and scheduling can
still cause contention. Builders remain thread-confined, including save/setter use.

When both locks are needed the order is provider then local. Closing first marks
the lifecycle under local, releases it, then waits for the provider gate. It never
waits for provider work while holding local. In-flight provider operations protect
the root through the gate; local TOTP protects its resolved secret through local.
Final wiping holds both locks after provider work has finished. No secret is
copied into a public projection to achieve this separation.

`state()` and all descriptive projection/competition accessors do no configured-
store I/O. Descriptive projections are immutable and thread-safe for reads.
`requestRefresh()` is non-blocking. `generateTotp(alternative, instant)` uses only
session-owned secret material and bounded local crypto, with no configured-store
I/O and no provider-gate acquisition. It returns deterministic code and a
half-open `[validFrom, validUntil)` interval. Time must be nonnegative. Explicitly
selected historical, conflicting and tombstoned alternatives all work.

The facade serializes configured-provider observation/write operations per
session. Clients need not serialize them. It does not coordinate independent
sessions/processes or claim arbitrary provider thread safety. Subscribers each
have serialized callbacks; different subscribers may execute concurrently.

Close marks the session closing before waiting on the provider gate, rejecting
new secret-backed work with `SessionClosedException`. An operation still definitely
prepublication may return Failed. An in-flight provider mutation is allowed to
finish as Saved or PublicationUncertain; close waits before wiping the root and
owned secrets and releasing storage. Prior uncertainty is never downgraded.
Descriptive states, descriptors, metadata and diagnostics remain readable.
Builders, TOTP, partial save, retries, refresh and password change require an open
session. Repeated close is harmless. Wiping and temporary cleanup do not claim
JVM secure erasure or additional durability.

Nulls, foreign references, mixed-token selections, wrong-merge secret choices,
closed builders/handles, setters after publication and retry after consumption
are exceptions, not persistence result variants.

## Boundaries and non-goals

The existing public `format` storage interfaces and the new `ApplicationVaults`
bridge are provider/internal boundaries needed by the two-module build, not normal
application API or a frozen third-party SPI. Application code needs only
`org.totipo` and `NioTotipo`. Package-private codecs, graph, fold and crypto stay
package-private. The facade does not change protocol encoding or r18 semantics.

Deployment/sync remains separate: there is no replication, remote acknowledgement,
rollback resistance, device enrollment, recovery-crypto change, UI, QR scanner,
platform qualification expansion, automatic winner, or field-level CRDT here.
Evidence remains the local case-sensitive Linux provider suite and pinned r18
corpus, not independent interoperability, universal crash safety or other-platform
qualification.

## r18 conformance scope and application responsibilities

README scopes v1 core conformance to the protocol foundation operations and v1 store
conformance to qualified NIO storage with the applicable core orchestration. No v1
application conformance is claimed. The term application API describes a library
boundary; it does not establish conformance of a desktop or Android application.

The [focused §12 audit](review/V1_R18_CAUSAL_FACT_METADATA_REPORT.md) resolves the
previous historical-metadata qualification. `ApplicationSession.CausalFact` retains
causal/topological facts derived from a validated TOKEN but does not retain or
represent that TOKEN object itself. Its OBJECT_ID-keyed token/parent links are
private, used only for same-token containment during merge checks. Observation
replaces the current index; captured states and merge bases may keep older links.
They cannot reconstruct historical values, metadata or heads from this index.
Session-interned complete values are semantic projections with no historical
OBJECT_ID lookup; captured alternatives retain their own heads and exact metadata.

Audited facade TOKEN projections and metadata handling in create/update/merge,
including additional-conflict states, partial resolution, folds and frozen retries,
are included in the corresponding core-conformance operations. An editor authors
new objects with explicitly supplied operation metadata, absent by default; it does
not replace or inherit the metadata of its parents. §12 requires exact metadata
while an object representation is retained, not indefinite historical persistence.
There is no blanket certification of every facade operation or application behavior.

Callers have the following information for implementing r18 application behavior:

| Requirement | API support and application responsibility |
| --- | --- |
| Empty-password intent | The caller supplies `char[]` and knows if it is empty. Empty UTF-8 remains format-valid for creation and reading. Interactive applications must obtain explicit confirmation before empty-password creation; the library supplies no dialog. |
| Possible existing vault without bootstrap | Before transferring store ownership to `Totipo.create`, provider integrations can inspect `TotipoStore.readVault` and `scanObjects`, including observed direct-child names and incomplete-scan results. Exactly 64 lowercase hex names are unauthenticated context; applications should warn and confirm during available observation. Creation neither requires exhaustive enumeration nor vetoes orphan-looking entries. `NioTotipo.create` has no pre-creation orphan diagnostic/result: a convenience-only caller cannot receive this context through that method. Flag any need for a facade diagnostic for human review; no new API is added here. |
| Current/historical/stale | Compare captured head revision IDs with the latest observed state's heads. Old states remain readable and their complete alternatives remain usable while the session is open. An incomplete or rolled-back observation does not prove freshness or supersession; the library supplies no universal historical/current certification. |
| Conflict and equal-valued distinct heads | `TokenState.hasConflict()` reports distinct complete values; `alternatives()` groups equal values while `heads()` retains every distinct current identity and its metadata. Applications must disclose both kinds of alternatives truthfully. |
| Tombstone | `TokenAlternative.descriptor().status()` exposes lifecycle state. Tombstones still have complete credentials and allow explicit TOTP; applications must not promise erasure. |
| Missing ancestry and unavailable observation | `unresolvedReferences()`, `VaultState.observation()` and `diagnostics()` report known gaps. Diagnostic reason strings do not identify arbitrary unreadable candidate objects in the facade; the SPI exposes entry names and read results. Per-object unavailable attribution through the facade is a human-review limitation. |
| Complete-known vs unavailable | Represented alternatives contain validated complete values; missing/unreadable ancestry has no synthesized value. Absence from observation does not prove deletion or a complete unknown value. |
| Newly learned resolution alternatives | Merge reobserves; `SaveResult.AdditionalConflict` returns the latest state and an explicit partial-resolution capability when a relevant alternative is newly learned, including a distinct equal-valued head. The application performs disclosure and the decision. |
| Exact represented-head metadata | `TokenHead.metadata()` exposes exact optional name and optional unsigned-u64 time bits; it preserves absent/present-empty and absent/zero distinctions. Captured heads preserve these distinctions after later observations, source disappearance and session closure. |
| Password rewrap | `PasswordChangeResult` distinguishes changed/authentication-failed/stale/failed/uncertain. Applications must describe same-root rewrap truthfully and recover uncertainty by observation/opening. It is not a full security reset. |

The root-compromise guidance in §8.1 is informative and defines no migration or
re-key protocol. Cycle-safe traversal and defensive same-ID exclusion remain
required despite the informative constructibility notes. UI wording, untrusted-text
rendering, warnings and confirmation belong to the consuming application.
