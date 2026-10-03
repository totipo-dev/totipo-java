# Experimental storage-provider boundary

This document describes the implemented Java storage-provider boundary. It is
not part of the Totipo wire-format specification. The SPI is experimental / not
frozen yet: there is no long-term third-party source or binary compatibility
promise. The normal application entry point remains `org.totipo` together with
`org.totipo.storage.nio.NioTotipo`; applications need not construct SPI values.

> The storage provider understands the Totipo storage layout, not the Totipo protocol.

```text
application
    -> org.totipo application API
    -> core protocol/application implementation
    -> org.totipo.spi.TotipoStore
    -> NIO provider

<root>/
    vault
    objects-v1/
```

## Scope and types

The provider knows the configured root, exact canonical lowercase child `vault`,
the exact `objects-v1` namespace, exact direct-child names, storage kinds,
observed logical content lengths, bounded reads, opaque immutable publication,
noncanonical staging, canonical installation/replacement, and durability
acknowledgement. It may create provider-owned temporary representations.

It does not know TokenId, RevisionId, VaultFingerprint meaning, K_root,
password authentication, ObjectId or canonical object-name grammar, envelopes,
TOKEN syntax, parents, heads, graph/fold, merge/conflict semantics, TOTP,
freshness/rollback policy, authorization, or sync.

All provider-facing types live in `org.totipo.spi` and import no domain or crypto
types:

| Type | Role |
| --- | --- |
| `TotipoStore` | Cohesive synchronous store and lifetime owner |
| `ObjectName` | Exact direct-child name value; no protocol grammar |
| `ObjectEntry` | Name, observed kind, optional observed logical byte length |
| `EntryKind` | REGULAR, DIRECTORY, SYMLINK, OTHER, UNKNOWN |
| `ObjectScan` | Complete or Incomplete enumeration with retained observations |
| `BoundedRead` | Exact-sized read and distinct failure/size outcomes |
| `ObjectWrite` | Immutable create-or-confirm-exact publication outcome |
| `VaultPrepare` | Prepared handle or definite preparation failure |
| `PreparedVault` | One actual staging representation and one mutation attempt |
| `VaultInstall` | Installed, AlreadyPresent, Failed, Uncertain |
| `VaultReplace` | Replaced, Failed, Uncertain; no STALE |
| `StoreFailure` | UNAVAILABLE, UNSAFE_NAMESPACE, UNSUPPORTED |

The interface offers only `readVault(expectedBytes)`, `scanObjects()`,
`readObject(name, expectedBytes)`, `publishObject(name, bytes)`,
`prepareVault(bytes)`, and `close()`. It has no protocol operations.

## Exact names and enumeration

`ObjectName.value()` preserves the exact supplied or observed Java string. It
does not fold case, normalize Unicode, resolve aliases, or establish an ObjectId.
Providers reject names that cannot safely identify one direct child. NIO rejects
empty names, dot/dot-dot, absolute paths and multi-component paths; this is path
safety, not Totipo filename grammar.

A scan makes one complete direct-child enumeration attempt of the exact
`objects-v1` directory. It exposes canonical-looking names, junk, uppercase
names, temporary names, directories, links and other kinds. It never recurses.
Names come from actual directory entries, not reconstructed lookup paths.
Case-distinct and normalization-distinct names remain distinct. Results contain
no duplicate exact names and defensively copy the entry list.

Both provider scan collection and SPI result validation sort by exact Java
String value and check adjacent names. They do not use attacker-controlled
hash-table lookup for duplicate detection. An anomalous duplicate in a NIO
enumeration is retained once and makes the scan Incomplete; duplicate exact
names supplied to a public ObjectScan constructor are rejected. Case and
Unicode normalization differences remain distinct.

Kind and optional length are enumeration-time observations only. Length is
logical content bytes, never allocated blocks. NIO reports length for regular
files and leaves it empty for other kinds. Failed metadata observation preserves
the name with UNKNOWN kind, empty length, and marks the scan Incomplete. No
inode, owner, timestamps, permissions or other filesystem metadata cross the SPI.

> Entry kind and content length are observations from the scan, not authoritative filters for later object reads.

Core recognizes protocol-relevant exact names first and freshly calls readObject
for every canonical-looking v1 name, including DIRECTORY, SYMLINK, OTHER and
UNKNOWN scan entries. A fresh WrongKind contributes unavailable-object evidence
under the existing observation rules; a fresh Present may be validated normally.
Irrelevant junk names are not probed.

Complete means the provider safely reached the end of this enumeration attempt.
It establishes neither an atomic namespace snapshot nor remote completeness,
freshness, rollback resistance, or simultaneous existence of the returned
entries. Incomplete retains already-observed entries; core may project their
valid contents but cannot treat absence as proof that no other relevant object
exists. Core translates incompleteness into its existing discovery diagnostics
and merge-freshness behavior.

Positively absent `objects-v1` maps to Complete with an empty list, preserving
r18 behavior. Scans and reads never create it. An unsafe/unavailable namespace
maps to Incomplete. An alias of the canonical namespace is never enumerated as
canonical; NIO detects a lookup collision without an exact directory-entry
spelling as unsafe. A distinct uppercase sibling on a case-sensitive filesystem
is unrelated.

## Fresh bounded reads

`readObject` accepts only ObjectName, never ObjectEntry. It freshly locates the
exact actual direct child and reobserves kind and bytes. Prior scan metadata is
not a read precondition: a 1024-byte regular file can later be a 17-byte file, a
symlink, or absent. `readVault` applies the same rules only to the exact lowercase
root child `vault`; `VAULT` never becomes canonical input.

| Result | Meaning |
| --- | --- |
| Present(bytes) | Exact target is regular; complete safely read content has exactly expectedBytes |
| Undersized(n) | EOF observed after exactly n bytes, n less than expectedBytes |
| Oversized | At least one extra content byte observed; no truncated prefix returned |
| Absent | Exact-name absence positively established |
| WrongKind(kind) | Exact target observed as a nonregular entry |
| Unavailable(reason) | Required state/read cannot safely be established |

NIO consumes at most expectedBytes + 1 content bytes, using bounded reads rather
than size metadata to decide EOF/extra-byte outcomes. Bounds are nonnegative
ints; negative bounds are programmer errors. Reading the possible extra byte
separately avoids integer overflow at Integer.MAX_VALUE.
Present defensively copies input/output arrays. A disappearance after selecting
an exact child can be Unavailable rather than a claim of stable absence.

Exact selection uses string equality against actual enumerated names. No case
or normalization alias can supply Present. No recursive resolution or final
symlink following is permitted. NIO checks kind without following links and
opens content with NOFOLLOW_LINKS. As with the previous provider, local OS,
mount/process namespace and same-privilege processes are trusted; these checks
do not invent descriptor-pinned snapshots or adversarial-namespace CAS.

## Immutable object publication

`publishObject` accepts an exact direct-child name and opaque caller-owned bytes.
It neither mutates the array nor retains it after return without copying. It
does not derive an identity, validate a name against bytes, authenticate an
envelope or inspect TOKEN/graph semantics.

Publication is create-or-confirm-exact and never overwrites existing different
bytes:

* Written: newly installed exact child with positive configured durability
  acknowledgement.
* AlreadyPresentExact: existing exact child has the supplied bytes and the
  required durability acknowledgement has been established. Equality alone is
  insufficient; an exact retry can recover known success after uncertainty.
* ExistingDifferent: exact child contains different bytes and was not replaced.
  Core owns any integrity interpretation.
* Failed: this invocation provably did not change the exact target.
* Uncertain: mutation may have occurred without the required acknowledgement.

For every new object publication, NIO ensures the exact safe objects-v1 namespace
exists and positively acknowledges the root-directory durability barrier before
entering object-target mutation. This stateless rule applies to pre-existing
namespaces as well as newly created ones; it never relies on process-local
knowledge of whether an earlier provider synchronized namespace creation.
Root-barrier failure is Failed with the target untouched by this invocation,
including after closing and reopening the provider.

NIO then writes and forces noncanonical staging, installs with an exclusive
hard link, and forces the installed representation and its directory.
The object mutation boundary is entry to the exclusive-link operation, after
the root barrier and staging force. Unacknowledged errors after that boundary
are Uncertain unless no mutation is positively established (such as a definite
exclusive-create collision). Exact-existing SPI retries retain their stronger
recovery barrier and force
the file and both objects directory and root, then confirm bytes again. A failed
retry barrier cannot acknowledge success. Case-alias collisions are never exact
existing success. Creating the namespace or leaving temporary artifacts without
publishing the exact object is compatible with Failed for that target.

## Explicit vault staging

`prepareVault` creates a noncanonical representation and never installs or
replaces `vault`. Prepared owns that representation; Failed means preparation
did not change canonical vault. Best-effort cleanup may leave abandoned
temporary artifacts; those have no protocol authority.

Core constructs and validates a candidate, prepares it, reads back the actual
stage, validates those exact staged bytes, and only then requests mutation.
`readBack(expectedBytes)` freshly observes the stage using BoundedRead.
Install/replace use that same stage; they never rebuild or re-upload a candidate
from the original caller array after validation. The established trusted-storage
model permits external races and provides no new CAS guarantee.

`installCanonicalIfAbsent()` returns Installed only after acknowledgement.
AlreadyPresent means exact lowercase vault existed and was not replaced.
An uppercase alias collision is a failure, never AlreadyPresent. Installation
never overwrites an existing canonical target.

`replaceCanonical()` attempts to make the exact staged representation canonical.
It returns Replaced, Failed or Uncertain, with no provider-level stale result.
Core authenticates BASE, builds the candidate preserving root, stages and
validates it, then freshly reads CURRENT. Absent/unavailable/unusable CURRENT
fails; a usable exact-byte difference is STALE; equality permits the replacement
attempt. No BASE or password is passed to the provider.

Replacement does not imply atomic move, a transaction, CAS, or compare-and-swap.
The SPI permits non-atomic move/copy/delete implementations. NIO attempts an
atomic move and uses a regular replacement move if atomic move is unsupported;
failures after mutation entry are conservatively uncertain. The retained legacy
low-level adapter preserves its older atomic-only capability contract.

A handle allows exactly one canonical mutation attempt, whether install or
replace, including Failed/AlreadyPresent outcomes. Repeated mutation or read-back
after consumption is a lifecycle error. Close is idempotent, abandons staging,
and performs best-effort cleanup. It never deletes/reverts canonical vault.
Cleanup failure cannot turn an acknowledged write into canonical uncertainty.
Store close also abandons remaining stages.

## Persistence certainty and exceptions

Failed requires evidence that this invocation did not change its canonical
target. An exception alone is not that evidence. Once a link/move/mutation may
have occurred, a lost acknowledgement, force failure, or provider error is
Uncertain unless absence of canonical effect is proved. NIO marks mutation entry
before the mutating operation; definite exclusive-link collisions and
pre-mutation failures remain distinguishable.

Successful results mean the configured provider positively acknowledged its
required durability work. They imply no remote replication/synchronization,
universal physical crash survival, rollback protection or peer observation.
`Saved` retains its application meaning.

Ordinary storage failures use result variants and coarse StoreFailure values;
programming/lifecycle errors may throw. Core remains conservative around
unexpected unchecked exceptions during publication, installation or replacement.
The legacy application publication machinery intentionally keeps uncertainty
monotonic after publication entry, even when a later SPI retry reports Failed or
ExistingDifferent. Only positive acknowledgements for the entire frozen operation
produce Saved. Vault lifecycle adaptation uses positive no-mutation evidence to
map Failed/AlreadyPresent without losing the Uncertain distinction.

Known structural namespace hazards consistently map to UNSAFE_NAMESPACE through
one shared NIO classification helper: non-directory/symlink namespace components,
unsafe nonregular publication targets and alias collisions without an exact
winner. Exact-name lookup is rechecked when a namespace may have been created
concurrently. Ordinary inability to observe/access state remains UNAVAILABLE;
unsupported operations remain UNSUPPORTED. A freshly observed nonregular read
target still uses BoundedRead.WrongKind, preserving the distinct read outcome.
No exception-message parsing or provider exception hierarchy crosses the SPI.

## Ownership, construction and migration

Passing a nonnull TotipoStore to `Totipo.open(store, password)` or
`Totipo.create(store, password)` transfers ownership for that call. The caller
must not subsequently use or close the store. Failure, including invalid password
input, closes it before returning/throwing; success transfers it to VaultSession.
Session close closes it exactly once, including repeated application close.
Calls on one store/its stages are serialized by core; providers need not implement
concurrent operations on a single handle. Cleanup is best-effort.

`NioTotipoStore.open(root)` observes an existing directory only. It creates no
vault, object namespace, canonical objects, repairs, normalization or cleanup.
Mutations occur only via explicit publication/preparation/mutation methods.

The normal path is NioTotipo -> NioTotipoStore -> Totipo -> core StoreAdapter ->
the proven application/protocol machinery -> VaultSession. StoreAdapter
interprets canonical object names and fixed v1 sizes exclusively in core.
It maps SPI outcomes onto DiscoverySource, V1ObjectPublicationStore,
VaultBootstrapStorage and VaultBootstrapReplacementStorage rather than rewriting
graph/fold or lifecycle logic. Size-only invalid read outcomes are represented
as invalid-length bounded streams for these legacy readers; no valid record is
manufactured.

ApplicationVaults is clearly superseded as a provider bridge. Its three-interface
overloads remain for existing low-level callers and tests, while its store-facing
overloads construct the internal adapter. New providers implement TotipoStore,
not those old interfaces. Legacy NIO wrappers delegate to shared layout-only
enumeration, publication and staging engines; they do not maintain independent
mutation implementations. StorageDurability remains the existing NIO-specific
directory acknowledgement capability.

No wire format, r18 semantics, crypto, TOKEN grammar, graph/fold, merge,
application projection, state-stream, or application persistence semantics are
redefined here. Existing conformance and facade tests remain authoritative.

## r18 scope qualification

The NIO provider and low-level core orchestration claim v1 store conformance for
observation, immutable object publication, initial VAULT installation, exact
compare-before-replace and replacement, and explicit durability-result handling,
subject to README's provider qualification. Core performs authentication and the
exact pre-replacement comparison; `replaceCanonical` itself is not atomic CAS.
Tests of abstract outcomes and accepted force calls do not establish physical
power-loss behavior on every provider or filesystem.

Pre-creation `scanObjects()` can expose possible orphan-looking names during
available observation, before ownership transfers to `Totipo.create`. These are
unauthenticated context, not proof of a recoverable vault or a creation veto.
Exhaustive enumeration is not required. Application warning/confirmation policy
and application conformance are outside this storage contract.
