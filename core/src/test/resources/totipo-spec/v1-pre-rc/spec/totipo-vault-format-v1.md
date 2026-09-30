# Totipo Vault Format v1

**Status:** design draft, revision 17  
**Protocol version:** 1  
**Revision:** r17  
**Scope:** encrypted complete-state TOTP assertions, causal interpretation,
canonical encoding, cryptography, and durable store operations.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY express normative
requirements. This is a pre-RC revision; r17 clarifies the threat model without
changing r16 protocol behavior or wire bytes. Earlier revision history is
historical, not an alternative grammar.

**Historical note:** v0 was an unreleased design draft. v1 defines no migration
protocol from v0. Historical artifacts are outside the v1 protocol.

## 1. Goals and authority

Totipo v1 operates on a configured durable object store. Synchronization is
optional and external. A local-only store, USB/removable storage, shared
filesystem, network mount, manually copied directory, or directory watched by
synchronization software uses the same protocol. Totipo validates and authenticates
what it observes; it does not cryptographically prove that the configured store
presents the complete or freshest valid history (Section 2).

TOKEN is the sole semantic object grammar. Each immutable TOKEN is a complete
assertion concerning one logical token. No value field is inherited. Explicit
parent references express causal incorporation; current values follow from the
valid observed objects, with concurrent disagreement preserved as whole-state
conflict. Possession of the unlocked vault root is the authority to author valid
vault state. There is no synchronized author identity object.

v1 does not define membership, secure deletion, garbage collection, root-key
rotation, consensus, or a global vault frontier. Future object families define
their own compatibility relationship to v1.

## 2. Threat model and storage boundary

Every configured-store entry and byte sequence that an implementation observes
MUST be treated as untrusted input and MUST obtain v1 protocol meaning only through
the applicable structural, cryptographic, and semantic validation. These checks
establish validity of the observed representation, not completeness or freshness
of the configured-store view.

Totipo v1 does not guarantee that the configured store presents a complete or
freshest view of vault history. A store may omit, remove, replay, restore, or
replace previously valid objects or VAULT representations without v1 necessarily
being able to establish that a fresher valid state once existed. v1 provides no
cryptographic rollback or deletion resistance for history no longer presented by
the configured store. A valid older representation may still authenticate
correctly. Without independent freshness/history evidence, v1 cannot in general
distinguish it from the freshest valid representation. Immutable content
addressing authenticates object identity; it does not authenticate the observed
set or its freshness.

This limitation MUST NOT weaken validation of observed candidate material:
applicable path/name/type rules, bounded reads, physical size, AEAD authentication,
padding and length, keyed OBJECT_ID, exact TOKEN grammar and semantic bounds, and
VAULT authentication still apply (Sections 3, 6, 11, 12, and 13). Stale but valid
authenticated material is distinct from forged or tampered bytes that fail these
checks.

The local kernel, filesystem implementation, process namespace, and processes
with the application's privileges are trusted for baseline conformance. Stronger defenses against
malicious same-privilege races are optional implementation hardening.

Without K_root, an attacker cannot decrypt TOKEN contents, compute keyed IDs
for guessed plaintext, or author new valid objects, assuming the cryptographic
primitives hold. A compromised unlocked client can read secrets and author valid
state.

The configured durable store is expected to retain successfully published objects
under ordinary successful operation. Success does not promise perpetual retention.
Protocol correctness MUST NOT depend on sync acknowledgement, peer count, remote
completion, provider snapshots, conflict-copy names, or remote version retention.
Local publication establishes no remote propagation or globally complete history.
The success, durability acknowledgement, and ambiguous-failure requirements for
immutable TOKEN publication, VAULT creation, and VAULT replacement (Sections 7,
8, and 18) remain mandatory; they describe what success means when Totipo writes,
not what history the configured environment continues to present later.

**Informative deployment note:** Freshness, rollback detection, retained history,
auditability, and stronger deletion resistance beyond Totipo's own publication
requirements may be supplied by the configured storage/synchronization environment
or additional application mechanisms. Deployments requiring these properties
need to select or provide them explicitly; v1 conformance does not assume them.
Such guarantees depend on that layer's trust and retention model; version history
alone is not cryptographic rollback protection. Synchronization remains optional.

No separate persistent graph database or local protocol object cache is required.
Implementation caches MAY hold validated bytes or derived indexes for performance;
they are reconstructible, disposable implementation details, not a second
normative object source. They MUST NOT silently supply missing store ancestry.
Loss of prior observations or application configuration is not protocol corruption.

## 3. Configured store and names

The layout is:

```text
configured Totipo store
    vault
    objects-v1/
        <lowercase OBJECT_ID>
```

`vault` is the exact lowercase ASCII, case-sensitive canonical bootstrap pathname.
VAULT denotes the bootstrap representation, not an alternate pathname.
Alternate-case names MUST NOT be used as automatic aliases or fallbacks. Only that
pathname is automatically opened as the bootstrap; temporary files, alternate
names, backups, and provider conflict copies do not compete with it. Applications
may expose them as diagnostic or explicitly selected recovery material.

When present, canonical `vault` MUST be observed as a regular file before it is
interpreted as a bootstrap. An observed symlink, directory, FIFO, socket, device,
or other non-regular entry there is not a valid bootstrap candidate and MUST NOT
be deliberately followed or interpreted as one. Diagnose/fail as appropriate;
no automatic fallback to another pathname is allowed.

When present, exact `objects-v1` MUST be observed as a directory to serve as the
v1 object namespace. An observed symlink, regular file, FIFO, socket, device, or
other non-directory entry there supplies no valid v1 namespace and MUST NOT be
deliberately traversed as one. The observed-entry rules are:

| Canonical entry | Accepted observed type | Absence |
| --- | --- | --- |
| `vault` | regular file only | creation may be attempted |
| `objects-v1` | directory only | no currently available namespace; lazy creation permitted |

These are accepted observed entry-type requirements, not proof against malicious
same-privilege races. They require no stable inode identity or particular platform
open/traversal primitive. Stronger race hardening remains optional under Section 2.
Namespace absence or wrong type produces no vault-wide operation gate and does not
invalidate already validated information under the normal observation model.

Only direct regular-file children of exact `objects-v1/` with exactly 64 lowercase
hexadecimal characters as names are object candidates. The name encodes the
32-byte OBJECT_ID. Readers MUST use bounded reads and allocations, MUST NOT
deliberately follow observed symlinks, and MUST ignore subdirectories, special
files, temporary/conflict names, and unrelated names. Metadata is not authentication.

Unknown sibling namespaces are outside v1 interpretation; their presence alone
creates no semantic state or operation block. Do not recursively scan them for
v1 objects. `objects-v1/` MAY be created lazily. Different roots MUST NOT
intentionally share this namespace. Observed orphan files do not prevent initial
VAULT creation (Section 7).

## 4. Cryptographic suite

v1 fixes the following primitives:

| Purpose | Primitive |
|---|---|
| Password KDF | Argon2id, version `0x13` |
| Root/subkey derivation | HKDF-SHA-256 |
| Private content addressing | HMAC-SHA-256 |
| Semantic object encryption | AES-256-GCM, 16-byte tag |
| Root-key wrapping | AES-256-GCM, 16-byte tag |
| Random values | platform CSPRNG |

The v1 Argon2id parameters are:

```text
memory       = 65536 KiB
iterations   = 3
parallelism  = 4
salt         = 16 bytes
output       = 32 bytes
secret K     = empty byte string
associated X = empty byte string
version      = 0x13
```

These parameters match the RFC 9106 second recommended Argon2id profile.

The number of execution threads used to evaluate the four Argon2 lanes is an implementation detail.

## 5. Password bytes

The format password domain is exactly `0..1024` bytes of well-formed UTF-8. The empty UTF-8 byte string is format-valid.

A character/string password MUST be encoded to UTF-8 strictly. Encoding errors, including unpaired surrogate code units in APIs capable of representing them, MUST be rejected rather than replaced. Pre-encoded password bytes MUST be validated as well-formed UTF-8.

The protocol performs no Unicode normalization. Applications MUST NOT silently normalize, trim, case-fold, or otherwise transform password bytes before Argon2id.

Inputs longer than 1024 UTF-8 bytes MUST be rejected. Application policy MAY require a non-empty or stronger password for creation, but readers MUST remain able to process every format-valid password byte string.

A creation UI SHOULD warn or require explicit confirmation before creating a vault with an empty password. Applications MAY apply stronger local password policy at creation, but such policy MUST NOT make existing format-valid vaults unreadable.

## 6. Root and bootstrap encoding

At creation, generate `K_root = CSPRNG(32 bytes)`. It is the cryptographic
identity of one vault. The password wraps K_root; it is not the object encryption
key. Changing K_root creates a different vault. Re-encryption does not undo prior
credential disclosure; exposed credentials SHOULD be rotated with their issuers.

The bootstrap is exactly 87 bytes, not TLV:

```text
offset  size  field
0       10    MAGIC = ASCII("TOTIPO-VLT")
10       1    BOOTSTRAP_VERSION = 0x01
11      16    ARGON2_SALT
27      12    WRAP_NONCE
39      32    WRAPPED_ROOT
71      16    WRAP_TAG
```

On every creation or password rewrap, generate fresh CSPRNG salt (16 bytes) and
nonce (12 bytes). Derive K_wrap from the exact password and salt using Section 4.

```text
VAULT_HEADER = MAGIC || BOOTSTRAP_VERSION || ARGON2_SALT || WRAP_NONCE
WRAPPED_ROOT || WRAP_TAG = AES-256-GCM-Seal(
    key = K_wrap, nonce = WRAP_NONCE, plaintext = K_root,
    AAD = VAULT_HEADER, tag_len = 16)
```

Readers MUST first apply the canonical regular-file entry rule in Section 3.
Readers MUST reject incorrect size, magic, bootstrap version, or invalid password
bytes before running Argon2id. Readers MUST authenticate the wrapping before
using the recovered root. The VAULT record is an offline password verifier;
anyone possessing it may attempt password guesses.

## 7. Initial VAULT creation

Canonical `vault` absence is sufficient to attempt creation. An observed wrong-type
entry is not absence and MUST NOT be treated as permission to overwrite it.
Implementations MUST
NOT require exhaustive enumeration or proof that objects-v1 is empty. Observed
orphan/object-looking files MAY produce an application diagnostic but do not block
creation and are not deleted by creation. Independent-root objects will not
authenticate under the newly generated root except with negligible probability.

Generate the root and construct the complete canonical representation separately.
Use the strongest reasonable crash-safe publication mechanism available; MUST NOT
knowingly overwrite an existing canonical `vault`. Attempt the required file/storage
and containing-namespace persistence before reporting success. If successful
creation without knowingly overwriting an observed existing `vault` cannot be
established, MUST NOT report success. No specific atomic no-replace primitive or
platform syscall is required. Creation completes when durable publication is
believed successful; there is no subsequent mandatory local establishment step.

## 8. Password change and VAULT replacement

Password change rewraps the same K_root with fresh salt and nonce. Construct the
complete replacement separately; MUST NOT deliberately truncate and rewrite the
canonical file in place. Use the strongest reasonable crash-safe replacement
mechanism available and attempt replacement/file and containing-namespace
persistence before success. Success means the implementation believes its required
durability work succeeded.

The operation is based on `BASE`, the exact canonical bytes it successfully opened.
Immediately before replacement, the implementation MUST re-observe the canonical
`vault` as an acceptable regular file and compare the exact current bytes to BASE.
If it cannot be re-observed as that regular file, or the exact-byte comparison
cannot be performed, MUST NOT report success. If `CURRENT != BASE`, MUST NOT knowingly
overwrite the intervening representation and MUST report stale/unsuccessful.
VAULT_FINGERPRINT MUST NOT substitute for this exact-byte freshness comparison.
No generation counter is introduced.

Atomic compare-and-swap is not required. A residual race after comparison is
accepted on stores without stronger facilities. Locks or native conditional
replacement MAY harden an implementation; no remote serialization is implied.

An ambiguous failure MUST NOT be reported as success or as proof that either
representation won. It creates no persistent pending state or required journal.
The next ordinary open interprets canonical `vault` actually present. Retained old
wrappers and their old passwords can still recover the same root. Password change
does not revoke historical wrappers or provide rollback protection.

## 9. Vault recognition

Define the exact domain, with no terminating NUL:

```text
VAULT_FINGERPRINT = HMAC-SHA-256(K_root, ASCII("totipo/v1/vault-fingerprint"))
```

The 32-byte fingerprint is stable for one K_root, unchanged across password
rewraps, and differs for independently generated roots except with negligible
collision probability. It is non-secret recognition data, not authorization,
freshness, first-contact authentication, or rollback protection.

An expected fingerprint is optional application configuration. After successful
unlock, mismatch means “different vault than expected,” not invalid vault. A new
client needs no stored fingerprint. Losing that configuration does not invalidate
a vault, prevent authorship, or prevent computation with a known credential.

## 10. Object key hierarchy and identity

All domain strings below are exact ASCII without terminating NUL. HKDF uses
SHA-256; `||` means byte concatenation.

```text
PRK = HKDF-Extract(salt = 32 zero bytes, IKM = K_root)
K_id = HKDF-Expand(PRK, ASCII("totipo/v1/object-id"), 32)
K_object_root = HKDF-Expand(PRK, ASCII("totipo/v1/object-key-root"), 32)
OBJECT_ID = HMAC-SHA-256(K_id, P)
K_object = HKDF-Expand(K_object_root, ASCII("totipo/v1/object-key") || OBJECT_ID, 32)
nonce = first 12 bytes of OBJECT_ID
AAD = ASCII("totipo/v1/object") || OBJECT_ID
```

P is the exact canonical TOKEN semantic plaintext (Section 12). OBJECT_ID is
32 bytes and commits to all fields including metadata and parents. Identical
canonical assertions in one vault intentionally collapse to one content-addressed
object. No event identifier or random authoring nonce preserves indistinguishable
event multiplicity. Different metadata can produce distinct objects with equal
TokenValues. Keyed addressing prevents offline guessed-plaintext ID tests without
K_id.

## 11. Fixed encrypted envelope

Every valid object in objects-v1/ is exactly 1024 bytes.

```text
ENCRYPTION_PLAINTEXT = u16be(len(P)) || P || ZERO_PADDING
object file = AES-256-GCM-Seal(K_object, nonce, ENCRYPTION_PLAINTEXT, AAD)
object file size                  1024 bytes
AES-GCM tag                         16 bytes
encrypted plaintext               1008 bytes
authenticated semantic length        2 bytes
maximum semantic plaintext        1006 bytes
```

The tag follows the 1008 ciphertext bytes. Padding fills the remaining plaintext
space and every padding byte MUST be zero. No random or alternate padding is
permitted. Construct canonical P, compute its ID, derive its key/nonce/AAD, then
encrypt. Deterministic encryption uses a distinct derived key for each distinct
ID; accidental key/nonce reuse requires a cryptographic collision. Equality of
exact assertions within one vault is observable. Across independent roots, keys
and IDs differ.

The fixed shape simplifies bounded reading, storage validation, publication,
allocation, fixtures, and cross-platform interoperability. Hiding exact semantic
length is secondary. Variable-size authenticated encryption would be technically
viable; its length leakage is not a major security defect. This choice is not
primarily a filesystem-block-size optimization.

The maximum legal TOKEN is 1005 semantic bytes (Section 12), fitting the 1006-byte
capacity with one spare byte. Shrinking would reopen settled field limits or the
four-parent invariant. A larger envelope has no current semantic justification;
bucketed sizes add unnecessary canonicalization complexity. v1 reserves no
speculative in-family semantic-version headroom.

## 12. Canonical TOKEN grammar

TLV framing is `TAG:u16be || LENGTH:u16be || VALUE[LENGTH]`. Integers are
unsigned big-endian. The following registry and order are exact; every field is
mandatory exactly once except PARENT_ID repetitions and the two optional fields.
No unknown, nested, duplicate, reordered, or trailing TLV is accepted.

| Tag | Field | Value |
| --- | --- | --- |
| 0x0001 | TOKEN_ID | exact 32 bytes |
| 0x0002 | PARENT_COUNT | exact u16be, 0..4 |
| 0x0003 | PARENT_ID | exact 32 bytes, repeated PARENT_COUNT times |
| 0x0004 | STATUS | exact u8: 1 LIVE, 2 TOMBSTONE |
| 0x0005 | ISSUER | 0..256 UTF-8 bytes |
| 0x0006 | ACCOUNT | 0..256 UTF-8 bytes |
| 0x0007 | ALGORITHM | exact u8: 1 SHA-1, 2 SHA-256, 3 SHA-512 |
| 0x0008 | DIGITS | exact u8: 6, 7, or 8 |
| 0x0009 | PERIOD | exact u32be: 1..2^32-1 seconds |
| 0x000a | SECRET_BYTES | 1..128 raw bytes |
| 0x000b | CLIENT_NAME | optional, 0..128 UTF-8 bytes |
| 0x000c | CLIENT_TIME | optional, exact u64be Unix seconds |

```text
TOKEN_ID
PARENT_COUNT
PARENT_ID...   # exactly PARENT_COUNT occurrences
STATUS
ISSUER
ACCOUNT
ALGORITHM
DIGITS
PERIOD
SECRET_BYTES
CLIENT_NAME?
CLIENT_TIME?
MAX_PARENTS = 4
```

A new logical TOKEN_ID MUST be independently generated by CSPRNG(32 bytes).
Updates, deletion, restoration, and folds retain that ID. No semantic restriction
on an otherwise exact 32-byte TOKEN_ID is imposed by readers.

Parents MUST be sorted by unsigned lexicographic byte order and duplicate-free.
`0 <= PARENT_COUNT <= 4` applies to every object irrespective of field lengths.
A parentless TOKEN is valid; multiple roots with the same TOKEN_ID are concurrent.

Strings MUST be well-formed UTF-8, counted in bytes, with no normalization,
trimming, case folding, or locale transformation. Embedded NUL and control
characters do not invalidate UTF-8. Presentation SHOULD escape or safely render
untrusted text without altering stored values or treating it as markup/code.

CLIENT_NAME absence and present empty string are distinct on the wire.
CLIENT_TIME absence differs from zero; zero is an ordinary value, not a sentinel.
Both fields are informational and may be inaccurate. Subject to their canonical
encoding/width rules, their presence or values MUST NOT affect TokenValue validity,
authorization, equality, causal ordering, parent/head selection, conflict
resolution, or TOTP. CLIENT_TIME MUST NOT establish freshness or winner priority.

For as long as a validated TOKEN object is represented, returned, exposed, or
retained by an implementation, its CLIENT_NAME and CLIENT_TIME metadata MUST be
preserved exactly with that object: presence versus absence, present-empty name
versus absence, exact validated UTF-8 bytes/value, and absent time versus zero or
any other exact unsigned u64 value. While representing that object, implementations
MUST NOT normalize, synthesize, replace, merge, arbitrarily select, or discard its
metadata. Metadata belongs to its individual object.

Metadata preservation does not require persistent retention of a TOKEN object,
its metadata, or its graph facts after the configured store no longer supplies it.
It creates no advisory-history, remembered-head, protocol-cache, or cross-run
persistence requirement. Optional caches remain disposable; a fresh client may
derive state from the currently available configured store. If an object is still
represented or retained, its metadata must stay exact. The protocol does not require
keeping that representation or its metadata merely because it was previously observed.
The operation-wide fold metadata rule in Section 17 remains unchanged.

Mandatory framing and fixed-width fields cost 77 bytes before variable values
and parents. Maximum non-parent fields cost
`77 + 256 + 256 + 128 + (4 + 128) + (4 + 8) = 861` bytes.
Four explicit parents cost `4 * (4 + 32) = 144` bytes.
Thus the maximum legal TOKEN is `861 + 144 = 1005` bytes; every legal value
always fits four parents.

## 13. Reading and exact validation

A reader MUST validate the canonical filename and exact 1024-byte size, derive
the object key/nonce/AAD, authenticate/decrypt, check semantic length at most
1006 and all-zero padding, recompute and match the keyed OBJECT_ID, and validate
the exact Section 12 grammar and field rules. Only objects passing all checks
contribute TOKEN state. Authenticated nonmatching grammar contributes no TOKEN
state; there is no alternative semantic dispatch within objects-v1/.

Invalid entries may produce diagnostics. A malformed or unavailable parent does
not invalidate a valid complete child. No file mtime, filename outside the canonical
namespace, or claimed metadata substitutes for authentication.

If two distinct successfully authenticated canonical TOKEN plaintexts validate
under the same OBJECT_ID, an implementation MUST NOT choose arbitrarily between
them. It MUST treat that object identity as an integrity/cryptographic failure
and exclude it from normal semantic evaluation; references to it remain unresolved.
This is distinct from exact-identical content collapse. No persistent continuity,
reset, or recovery state machine is required.

## 14. Observation and diagnostics

Evaluation receives valid observed TOKEN objects, unresolved parent references,
and diagnostics. It MUST NOT require exhaustive enumeration. Unreadable files,
wrong sizes, failed AEAD, invalid grammar, enumeration errors, resource limits,
and disappearance during observation may be diagnostic evidence. Those diagnostics
MUST NOT globally invalidate already validated objects or prohibit protocol
operations. Implementations SHOULD continue useful processing where practical.

Claims such as “this is every token,” “no other branch exists,” or “no other
TOKEN_ID exists” are not required. Optional inventory features are application
features. Every current-state description is relative to the valid object set
being evaluated, not proof of freshness or completeness. Later observations cause
ordinary recomputation. Loss of old objects does not invalidate remaining objects
or supply a reason to invent missing ancestry.

Disappearance or presentation of an older valid store view MUST NOT cause a crash
or turn lack of freshness evidence into protocol facts. Implementations MUST
derive current observable state from the available validated inputs under
Sections 15 and 16 and truthfully report unresolved references. A missing object
MUST NOT be treated as having never existed within the currently supplied graph
facts, nor may an unresolved parent be silently skipped. Reappearance of valid
objects permits ordinary recomputation. This requires no cross-run remembered
history; a fresh client may know only what the configured store currently supplies.

## 15. Causal equivalence and current heads

Within one TOKEN_ID, resolve a child-to-parent edge only when the referenced ID
is available as a valid TOKEN of that same TOKEN_ID. Otherwise leave the edge
unresolved, including a reference to a valid object of another TOKEN_ID.
Implementations MUST NOT invent ancestry, skip unavailable parents, infer unseen
grandparents, or reconstruct unobserved history. A later valid parent may resolve
an edge through ordinary recomputation.

Reachability follows zero or more resolved child-to-parent edges. Define:

```text
A ≡c B iff A reaches B and B reaches A
```

These causal-equivalence groups are the strongly connected components (SCCs).
Conceptually collapse them to a DAG. A group is maximal/current when no distinct
group is its strict descendant: no distinct group reaches it. Current heads are
every TOKEN object belonging to every maximal causal-equivalence group.

Heads remain complete validated TOKEN objects, exposing their OBJECT_ID, parents,
TokenValue, and exact CLIENT_NAME / CLIENT_TIME presence and values for truthful
presentation. The semantic-value projection may ignore metadata for equality;
it MUST NOT erase metadata from head objects or choose a synthetic metadata winner.
Every member of a maximal causal-equivalence group retains its own metadata.

Members of one group are equally current; no representative wins. A strict
descendant of any member supersedes the whole group. Resolved cycles are ordinary
causal equivalence, not fatal integrity failures or operation blocks. Traversal
MUST be cycle-safe and bounded by available resources. Resource limits remain
diagnostics under Section 14.

For A <-> B, both are heads if their group is maximal. If D lists A and no object
descends from D, D supersedes both. Late arrival that completes a cycle simply
changes the groups and heads.

## 16. Complete values and truthful descriptions

TokenValue is the complete tuple `(STATUS, ISSUER, ACCOUNT, ALGORITHM, DIGITS,
PERIOD, SECRET_BYTES)`. Equality compares exact values/bytes in that tuple;
TOKEN_ID, parents, and client metadata are excluded. There is no field-level
merge or timestamp winner. Every object, including a TOMBSTONE, carries this
complete tuple.

Distinct TokenValues among current heads are ordinary whole-state conflict,
including within a single causal-equivalence group. Equal-valued current heads
represent one semantic value with multiple causal heads; equality does not make
one head an ancestor of another. No value is synthesized from several assertions.
For example, equal-valued heads A and B with CLIENT_NAME "Laptop" and "Phone"
represent one semantic TokenValue but retain both causal objects with A's and B's
respective metadata. The same rule applies to equal-valued members of a maximal
SCC; no representative metadata is selected. Historical objects likewise retain
their exact metadata whenever their validated object information is retained.

STATUS is lifecycle bookkeeping. TOMBSTONE marks deleted presentation state,
not an unusable or unavailable credential. Inspection and TOTP computation remain
permitted. Restoration is an ordinary complete assertion with STATUS = LIVE,
optionally changing other fields. No history reconstruction is needed to restore
a readable complete tombstone.

Applications MUST truthfully distinguish current, historical/stale, conflicting,
equal-valued current heads, tombstoned, unavailable, missing ancestry, complete
value known, and complete value unavailable as applicable. MUST NOT present a
historical value as unique current state, a conflict branch as conflict-free,
or a tombstone as ordinary active state without indicating deletion. Known
unavailability MUST NOT be silently omitted from claims of complete state.
These are descriptive obligations, not credential-use permissions. Any complete
known credential may be used for TOTP, including historical or conflicting values.

## 17. Authorship and bounded folding

A writer authors a complete desired TokenValue for one TOKEN_ID. For a new logical
token, generate a new CSPRNG TOKEN_ID as in Section 12, supply or generate the complete
desired TokenValue, and use an empty parent set. An update intended to incorporate the observed frontier MUST
incorporate all selected current heads, directly or through the fixed fold below.
A claimed resolution of all known alternatives MUST disclose newly learned
relevant alternatives before making that claim. Hidden or later-discovered history
may remain concurrent; it does not retroactively invalidate a published assertion.

Unavailability of history alone MUST NOT prohibit authorship when the TOKEN_ID and
complete desired TokenValue needed for the new assertion are otherwise known or
supplied. This applies to assertions about a known logical token without changing
the new-token creation rule above. Unknown history does not authorize inventing
its contents or ancestry; the required authoring inputs must still be supplied.
Known parent IDs may be referenced without their currently readable bytes.
Disappearance of history already considered does not stale an informed decision.
Previously learned facts do not become false on disappearance, but remembered facts
are not a second source of current store ancestry. Retention across runs is not
required. Confirmation is informational application/UI policy, not a persistent
protocol authorization object. Unrelated changes do not change the decision's
TOKEN context. New relevant alternatives call for disclosure, not a blanket
authorship prohibition.

For a selected frontier of at most four heads, one object lists all selected IDs.
For width N > 4, sort original heads lexicographically and use fixed linear folding:

```text
F1 <- A B C D
F2 <- F1 E F G
F3 <- F2 H I J
...
```

The first stage incorporates four original heads; each later stage carries the
previous fold plus up to three remaining originals. Sort each stage's encoded
parent IDs and remove no required original merely to fit. All stages MUST carry
the same complete desired TokenValue and the operation's exact client metadata:

| Field carried by every stage | Required preservation |
| --- | --- |
| TokenValue | same complete desired value |
| CLIENT_NAME | same exact presence and UTF-8 value, including present-empty |
| CLIENT_TIME | same exact presence and unsigned u64 value, including zero |

Metadata is optional for the authoring operation; absence MUST be preserved on all
stages when absent for that operation. Every stage MUST carry the same exact
CLIENT_NAME presence/value and CLIENT_TIME presence/value. Only the direct parent
lists differ according to the linear-carry fold; TOKEN_ID also remains unchanged.
MUST NOT independently omit metadata, refresh CLIENT_TIME, or change CLIENT_NAME
between stages. Stages do not represent separate UI authoring events. This
preservation rule does not give metadata any role in TokenValue equality, parent
selection, causality, conflict resolution, authorization, or TOTP. The final stage
causally incorporates every selected original through the constructed fold.
There are `ceil((N - 1) / 3)` stages for N > 4.

Each stage is an ordinary complete TOKEN. There is no multi-object transaction,
wire batch marker, or rollback of earlier published stages after a later failure.
Other clients may observe intermediate stages. Missing stages leave unresolved
edges. New alternatives may require a further assertion to make a resolution
claim accurate, without invalidating already published stages.

## 18. Immutable TOKEN publication

Publication addresses `objects-v1/<lowercase OBJECT_ID>` and supplies the complete
intended 1024 bytes. Construct bytes away from the canonical target. Implementations
MUST NOT deliberately publish by progressively filling or truncating a canonical
file. Use the strongest reasonable crash-safe publication method available;
attempt file/storage and containing-namespace persistence before reporting new
publication success. Report success only when the implementation believes its
required durability work succeeded. No particular syscall, atomic primitive,
mandatory reread, decrypt, or semantic self-validation is required at this layer.
Writer correctness and observation validation remain separately required.

If the exact intended bytes already exist at a regular canonical target, return
idempotent success after read-only exact comparison. MUST NOT rewrite, replace,
rename, touch, chmod, or otherwise mutate that entry merely to reconfirm it.
No fresh fsync or other persistence barrier is required merely for exact-existing
success, nor any semantic reread/decrypt.

If an existing target is non-exact, unsuitable, or cannot be established as exact,
leave it untouched and fail publication. MUST NOT repair or replace it in ordinary
publication. Ambiguous failure MUST NOT report success and MUST NOT infer absence.
No persistent publication-pending/unknown state is created. Later observation or
an exact retry handles recovery: absent permits another attempt, exact permits
idempotent success, different/unsuitable fails unchanged.

Parent availability is not a publication prerequisite. Lazy namespace creation
uses the same durability intent. Stores lacking atomic visibility can expose
intermediate effects despite a reasonable complete-byte staging strategy; this
does not create a new protocol state. Observed partial files are invalid diagnostic
evidence. Success promises neither perpetual retention nor remote completion.

## 19. TOTP computation

The flattened credential fields are:

```text
ALGORITHM
DIGITS
PERIOD
SECRET_BYTES
```

The credential is atomic.

v1 fixes:

```text
T0 = 0
PERIOD is integer seconds
PERIOD > 0
T = floor(Unix_time_seconds / PERIOD)
```

`Unix_time_seconds` MUST be non-negative.

The counter MUST fit in `0..2^64-1` and is encoded as unsigned 8-byte big-endian.

TOTP follows RFC 6238 with RFC 4226 dynamic truncation.

Supported algorithms:

```text
0x01 = HMAC-SHA-1
0x02 = HMAC-SHA-256
0x03 = HMAC-SHA-512
```

`DIGITS` MUST be exactly 6, 7, or 8.

`PERIOD` is `u32be` in `1..2^32-1`.

`SECRET_BYTES` is `1..128` raw bytes.

Newly generated secrets MUST be at least 20 bytes long and every byte MUST be generated by the platform CSPRNG.

v1 does not represent HOTP/event-counter credentials, `T0 != 0`, non-decimal/alphanumeric OTP formats, or digit counts other than 6/7/8.

Importers MUST NOT silently coerce unsupported credential types.


To compute a code, HMAC the eight-byte counter using SECRET_BYTES and the chosen
algorithm. Let offset be the low four bits of the final HMAC byte. Read four
bytes at that offset as big-endian, clear the high bit, reduce modulo 10^DIGITS,
and render exactly DIGITS decimal characters with leading zeros. STATUS and
client metadata do not enter the computation.

## 20. Conformance and remaining work

A conforming implementation implements the exact bootstrap, key derivations,
canonical TOKEN grammar, fixed envelope, causal-equivalence interpretation,
complete-state equality, TOTP, and the applicable store operations above.
Conformance evidence MUST cover valid and invalid bytes, metadata presence and
limits, four-parent bounds, maximum size, fixed folds, missing parents, equal and
conflicting cycles, descriptive tombstones, diagnostic-only incomplete observation,
fingerprint/rewrap stability, and truthful publication/replacement outcomes.
Abstract graph fixtures may model cycles and same-ID failures without pretending
to construct cryptographic collisions. Storage workflow fixtures model platform
outcomes; they are not proof of a particular filesystem's crash durability.

The repository moving pre-RC requirements profile pins this specification, schema,
manifest, and exact required cases. It is not a frozen RC profile. Historical
revision records do not confer compatibility with their old TOKEN bytes.

The next work is to repin/reconcile `totipo-java` against r16 and evaluate what
existing implementation architecture/code should be kept, changed, simplified,
or deleted. That work, platform/API selection, garbage collection, and future-family
migration are outside this rewrite.

## 21. Revision history

### v1/r17

Seventeenth v1 design draft. Threat-model clarification from r16:

- distinguishes hostile/untrusted observed content from completeness and freshness
  of the configured-store view;
- explicitly locates rollback detection, freshness, and retained-history guarantees
  beyond v1 at the storage/application layer, with synchronization still optional;
- makes no wire-format, cryptographic, graph, storage-publication, or semantic
  change and changes no conformance-case outcome.

### v1/r16

Simplifies to flattened TOKEN-only complete state with optional CLIENT_NAME and
CLIENT_TIME; removes DEVICE, provenance signatures, in-family semantic dispatch,
readiness and candidate-use gates, advisory history, and mandatory VAULT_BINDING.
Fixes four parents and linear folds, interprets cycles as causal equivalence,
retains the 1024-byte envelope and outer object cryptography, introduces stable
VAULT_FINGERPRINT recognition, and specifies platform-neutral durable publication
and exact compare-before-replace. TOKEN wire bytes intentionally change.

The following entries are preserved historical records of earlier revisions.

### v1/r15

This revision intentionally changes state semantics. Synchronized storage is explicitly unreliable and nontransactional. Writers use accepted local snapshots; later hidden history is normal concurrency. Optional local history becomes advisory regression evidence, with cache loss/corruption discarded rather than blocking operations. Durable graph transactions, history-persistence gates, global discovery/unscoped gates, mandatory opaque retention, and unavailable remembered-state confirmation are removed. Conflict confirmation tracks TOKEN-specific semantic decisions, not unrelated vault events. Ambiguous publication is normal uncertainty with permitted retries. Synchronized-object fsync becomes reliability guidance; exact-existing publication needs exact bytes. First DEVICE success uses publication acknowledgement. Local binding establishment no longer uses pending records; VAULT, binding, and private custody retain strong durability. Runtime writer self-roundtrips are optional hardening.

No wire-format, crypto, routing-prefix, envelope-family, object-size, capacity-formula, TOTP algorithm, or identifier construction changes.

### v1/r14

Fourteenth v1 design draft.

Local-filesystem threat-boundary simplification from r13:

- clarifies that the synchronization medium remains fully untrusted for contents, history, freshness, ordering, completeness, and availability;
- makes the local OS/filesystem execution environment part of the trusted computing base for baseline v1 conformance;
- removes the baseline requirement to prove immunity to an actively malicious same-privilege process racing pathname, file-type, directory-identity, or inode-content changes between individual filesystem operations;
- retains direct-family namespace confinement, exact filename rules, bounded reads, observed symlink/special-file exclusion, conservative handling of synchronization churn, and full cryptographic validation of synchronized bytes;
- retains immutable no-overwrite object publication, crash-safe VAULT replacement, durability acknowledgement, and publication-before-durable-graph ordering;
- classifies ordinary synchronization races as availability/freshness conditions causing retry/rescan/incomplete processing rather than invented authenticated state;
- permits stronger hostile-local-filesystem hardening as an implementation-specific defense rather than an interoperability requirement;
- does not change TOKEN/DEVICE bytes, cryptographic domains/construction, routing prefixes, `objects-v1/` layout, object size, capacity formulas, graph/state semantics, provenance semantics, or TOTP algorithms.

### v1/r13

Thirteenth v1 design draft.

Durable-recovery/provenance-completeness changes from r12:

- defines the minimum `OPAQUE_UNSCOPED_RECORD` and requires retention of the exact authenticated 1024-byte object so a later compatible implementation can reprocess it after synchronized deletion;
- makes failure to durably retain that exact opaque-unscoped object a `KNOWLEDGE_PERSISTENCE_BLOCKED` condition;
- explicitly warns that continuity reset/re-baseline may cause assertions previously known to be historical to re-enter the derived current/conflict frontier when prior ancestry knowledge is discarded;
- requires provenance status to be recomputed for affected known TOKEN assertions when matching DEVICE/public-key material later becomes available;
- aligns first-DEVICE conformance wording with the normative report-success gate: TOKEN bytes may be published first, but first TOKEN success is not reported until the matching DEVICE advertisement is durable;
- defines `resource-complete` discovery/baseline scans;
- clarifies that the four-parent fold in Section 47 is illustrative and state-size-dependent;
- clarifies DEVICE presentation wording and cleans section-separator/editorial artifacts;
- no TOKEN/DEVICE wire-format, crypto, routing-prefix, storage-family, capacity-formula, or TOTP algorithm changes.

### v1/r12

Twelfth v1 design draft.

State-machine/provenance hardening changes from r11:

- defines when `OPAQUE_UNSCOPED` evidence is active and makes synchronized disappearance explicitly non-clearing;
- adds an explicit user-directed continuity reset/re-baseline path that can abandon prior-epoch opaque-unscoped evidence only with acknowledgement of lost continuity guarantees;
- clarifies that present opaque-unscoped evidence is rediscovered and remains blocking after re-baseline;
- makes supported provenance-UNRESOLVED/REJECTED DEVICE heads presentation-inert but still part of DEVICE causality;
- requires DEVICE rename/convergence to incorporate every current supported DEVICE head regardless of provenance status;
- distinguishes hostile synchronized-byte corruption/unavailability from corruption/inconsistency of local durable security memory;
- requires cryptographically secure native/platform ECDSA nonce generation and forbids ad-hoc Totipo nonce generation;
- requires durable publication of the local DEVICE advertisement by the time first TOKEN publication for that device/vault is reported successful;
- documents that `K_signature_context` vault-binds otherwise vault-independent device provenance;
- clarifies empty-password creation UX, TOTP secret-generation wording, direct-HMAC `VAULT_BINDING` rationale, and the distinction between `OBJECT_VERSION` routability and official allocation;
- fixes stale revision/open-work wording and updates conformance requirements;
- no TOKEN/DEVICE wire-format, object-crypto, envelope-family, routing-prefix, size/capacity, or TOTP algorithm changes.

### v1/r11

Eleventh v1 design draft.

Governance, compatibility-clarification, and historical-cleanup changes from r10:

- clarifies that rolling-upgrade interoperability with future envelope families is cooperative and depends on the future writer publishing the required v1-family compatibility projection;
- assigns `OBJECT_VERSION = 0x01` to the current semantic grammar, leaves every other value unassigned, requires published-spec allocation for interoperable use, and defines no private-use range;
- records v0 as undeployed historical design work rather than a supported predecessor;
- removes the normative v0 migration procedure and renumbers subsequent sections;
- cleans stale/completed pre-RC work wording;
- no TOKEN/DEVICE semantic encoding, routing-prefix, storage-family, cryptographic, vector-expectation, or runtime-semantic changes.

### v1/r10

Tenth v1 design draft.

Envelope-family namespace changes from r9:

- renames the current object namespace from flat `objects/` to exact top-level `objects-v1/`;
- defines `objects-v1/` as the Totipo v1 envelope/storage-family namespace;
- clarifies that `OBJECT_VERSION` versions semantics inside this family rather than selecting the storage family;
- freezes 1024-byte object size as a v1-family property rather than a promise that every future Totipo family uses 1024-byte files;
- unknown sibling namespaces such as `objects-v2/` are outside v1 discovery and have no authenticated semantic meaning by themselves;
- differently sized files inside `objects-v1/` are invalid current-family storage evidence and never become opaque future-version evidence;
- `OPAQUE_ROUTABLE` / `OPAQUE_UNSCOPED` apply only after successful authentication of a valid v1-family envelope;
- a future envelope/storage family may use a separate sibling namespace and arbitrary future layout defined by that future specification;
- a future family claiming rolling-upgrade interoperability with v1 must publish authenticated v1-family compatibility assertions into `objects-v1/`;
- old v1 clients observe future-family state only through those compatibility assertions;
- future-family namespace names cannot be used by an untrusted sync provider to manufacture warnings/blocks;
- privacy/filesystem/conformance wording updated around family namespace isolation;
- no change to TOKEN/DEVICE semantic bytes, crypto construction, routing prefix, or 1024-byte v1-family object bytes beyond the storage path change.

### v1/r9

Ninth v1 design draft.

Forward-compatible rolling-upgrade changes from r8:

- freezes common TOKEN/DEVICE routing metadata across semantic versions in the v1 envelope family;
- TOKEN routing includes TOKEN_ID and AUTHOR_DEVICE_ID;
- DEVICE_ID is explicitly serialized as frozen DEVICE routing identity;
- v1 DEVICE validates serialized DEVICE_ID against the existing public-key derivation;
- defines supported-valid, opaque-routable, opaque-unscoped, and invalid compatibility classes;
- future TOKEN/DEVICE objects with valid frozen routing are retained as opaque durable graph nodes;
- opaque nodes participate in ancestry/current-head selection without parsing their body;
- opaque current TOKEN degrades only that token and keeps supported candidate use available;
- unrelated tokens continue normal operation;
- v1 authorship is blocked only for a token whose current frontier includes opaque future TOKEN semantics;
- opaque future DEVICE affects presentation/provenance scope, not TOKEN authority;
- opaque-unscoped authenticated future evidence blocks authoritative operations but not candidate use;
- later supported/readable descendants can causally supersede opaque future nodes;
- semantic version number never establishes ordering;
- common readiness predicates centralize authoritative vs candidate-use gates;
- maximum-display DEVICE planned fan-in drops from 15 to 14 parents because explicit DEVICE_ID adds 36 semantic bytes;
- degradation philosophy is explicit: uncertainty reduces assurance/capability rather than automatically making authenticated candidate material unusable.

### v1/r8

Eighth v1 design draft.

Pre-vector adversarial hardening from r7:

- resolved-edge cycles are graph-integrity failures and cannot participate in current-head suppression;
- one `OBJECT_ID` is globally unique across all semantic object types and immutable graph records;
- inconsistent TOKEN/DEVICE reuse of one ID forces local continuity recovery;
- writer capacity planning reserves 72 bytes for DER ECDSA signatures;
- writers may not exploit/retry shorter signatures to squeeze in extra parents;
- maximum-size TOKEN plans 4 parents; maximum-size DEVICE plans 15 parents;
- TOKEN and DEVICE wide-frontier fold progress is explicitly guaranteed;
- ordinary current use and semantic authorship remain `DISCOVERY_STATE=READY` only;
- explicit candidate use may proceed under `PROCESSING_INCOMPLETE` from an already authenticated LIVE candidate, with mandatory warning, when no stronger gate is active;
- unreadable candidate observations remain unprocessed rather than being treated as safely classified;
- unsupported-version blocking explicitly includes candidate use;
- credential-generation freshness snapshots are explicit for ordinary and candidate use;
- `AUTHOR_TIME` must be preserved as unsigned/raw u64 and platform date-conversion overflow cannot affect validity;
- extreme `AUTHOR_TIME` values remain structurally valid and non-causal;
- privacy/overview wording updated;
- at least two independent implementations are required before v1-rc1 freeze.

### v1/r7

Seventh v1 design draft.

Pre-vector hardening changes from r6:

- defines `DISCOVERY_STATE = READY | PROCESSING_INCOMPLETE`;
- visible/accepted-but-unprocessed object candidates block ordinary TOTP use, explicit candidate credential use, and semantic authorship until processed;
- broadens degraded fallback into explicit candidate credential use;
- user may explicitly generate from any available vault-authenticated LIVE TOKEN candidate when ordinary use is blocked by whole-state conflict or unavailable current values;
- candidate may be a current conflict alternative, an available current head while another is missing, or historical recovery material;
- candidate use never changes current-state semantics and cannot bypass unsupported-version, continuity, discovery, or knowledge-persistence gates;
- parent current-path/intrinsic-invalid observations leave unknown parent identities unresolved rather than creating rejected edges;
- durable DEVICE graph records retain `PUBLIC_KEY_X963`;
- known-object reappearance must match immutable durable graph identity/topology/public-key/timestamp records;
- detected durable-graph corruption enters local continuity recovery rather than silently dropping records;
- multi-object folds explicitly are not synchronized transactions;
- historical provenance UI caveat restored: current device friendly name is not historical friendly-name metadata;
- adds required common `AUTHOR_TIME` `u64be` field to TOKEN and DEVICE;
- `AUTHOR_TIME=0` means unknown; positive values are reported Unix seconds;
- author time is authenticated/signed informational metadata only and never affects causality, freshness, head selection, or conflict resolution;
- all objects in one multi-object fold use one common captured AUTHOR_TIME;
- TOKEN maximum-size formula becomes 215 + issuer + account + secret + 36×parents; maximum fields still fit four parents in the 1024-byte envelope;
- maximum-size DEVICE now fits 15 parents with AUTHOR_TIME.

### v1/r6

Sixth v1 design draft.

Major simplification from r5:

- removes durable accepted-head and superseded-ID summaries;
- introduces append-only durable authenticated TOKEN/DEVICE topology as primary local continuity/security memory;
- once a valid node and parent claims are durably learned, synchronized file deletion cannot erase that topology;
- current TOKEN heads are maximal nodes in the durable known graph;
- complete TOKEN value availability is tracked separately from graph/topology knowledge;
- a known current head may remain current while its value bytes are unavailable;
- older available TOKENs may be explicitly used in degraded stale mode with strong warning, without changing current-state semantics;
- reaffirmation is an ordinary complete TOKEN parenting all durable known current heads, including unavailable current heads;
- a remote TOKEN parenting a locally known unavailable current head advances normally when learned;
- removes `REFERENCE_COVERS_FOR_REAFFIRMATION`, reaffirmation records, `SUPERSEDED_ID_SET`, `ACCEPTED_HEAD_IDS`, and `ACCEPTANCE_PENDING`;
- bounded folds rely on durable intermediate graph nodes instead of local supersession summaries;
- detected graph/security-memory rollback enters `LOCAL_CONTINUITY_UNKNOWN`; baseline re-establishment rebuilds a fresh durable graph from a resource-complete current scan;
- first-open and pending-VAULT establishment procedures are explicit;
- introduces explicit degraded stale credential use for an older available LIVE TOKEN when a newer/current TOKEN value is unavailable.

### v1/r5

Fifth v1 design draft.

Consistency-hardening changes from r4:

- formally distinguishes `OBSERVED_TOKEN_HEADS`, `CURRENT_TOKEN_HEADS`, and durably `ACCEPTED_TOKEN_HEADS`;
- introduces `ACCEPTANCE_PENDING` and blocks unsafe authorship/credential consumption while a safety-relevant frontier change is not durably accepted;
- defines active staged multi-object TOKEN folds so an operation's own intermediate publications do not stale their confirmation;
- external safety-relevant observations during a fold stale confirmation and force recomputation;
- replaces reaffirmation-specific local historical state with one per-token `SUPERSEDED_ID_SET`;
- every successful multi-object TOKEN fold adds every original required input ID and every intermediate fold TOKEN except FINAL to `SUPERSEDED_ID_SET`;
- intermediate fold TOKENs such as `M1` are explicitly superseded after successful finalization;
- one-object ordinary writes do not require extra superseded bookkeeping unless performing missing-history reaffirmation;
- ordinary fold coverage requires resolved causal ancestry; missing-ID reference coverage is restricted to reaffirmation;
- unsupported authenticated semantic versions explicitly block both ordinary authorship and ordinary TOTP consumption;
- full crash-safe `VAULT` publication ordering restored;
- common `OBJECT_VERSION` / `OBJECT_TYPE` TLV prefix frozen across the v1 semantic-version family;
- explicit `LOCAL_CONTINUITY_UNKNOWN` baseline re-establishment procedure added;
- DEVICE wide-frontier rename fold defined;
- stale earlier-revision terminology cleaned up.

### v1/r4

Fourth v1 design draft.

Adversarial-hardening changes from r3:

- automatic remote handoff removed; another writer's TOKEN cannot clear this client's local known accepted-head-loss warning while the remembered object remains unavailable;
- local user reaffirmation is the sole mechanism for clearing such local missing-history evidence without restoration of resolved causal history;
- `REFERENCE_COVERS_FOR_REAFFIRMATION` narrowed to local reaffirmation finalization;
- every intermediate reference-chain TOKEN must be available and valid; only the exact locally remembered terminal head ID may be unavailable;
- finalized reaffirmation permanently records exact reaffirmed historical TOKEN IDs in local security memory;
- exact reaffirmed historical IDs are excluded from this established client's current frontier even if synchronized causal proof is later deleted;
- newly discovered descendants of reaffirmed historical IDs are never suppressed and may create new conflicts;
- loss of the newer covering head creates fresh known accepted-head loss; old historical state is not silently resurrected;
- durable local security memory must be independent of the hostile synchronized namespace;
- rollback/reset/deletion/loss of local security-memory freshness enters `LOCAL_CONTINUITY_UNKNOWN` and loses prior rollback-continuity claims until explicit baseline re-establishment;
- complete-state confirmations now bind to a monotonic token confirmation-context epoch and become stale on change-and-return or process restart;
- multi-object convergence/reaffirmation batches explicitly bind one confirmation to the entire original required identity set;
- optional same-root exact-VAULT representation fingerprint warning restored for password/bootstrap rollback visibility.

### v1/r3

Third v1 design draft.

Changes from r2:

- `TOKEN` no longer repeats the 65-byte P-256 public key;
- `TOKEN` carries `AUTHOR_DEVICE_ID[32]`;
- `DEVICE_ID = SHA-256("totipo/v1/device-id" || PUBLIC_KEY_X963)`;
- `DEVICE` carries the canonical 65-byte X9.63 public key and self-signature;
- TOKEN provenance may be verified using matching DEVICE/local key material;
- missing matching public-key material is `PROVENANCE_UNRESOLVED`;
- zero-length or bad signatures are `PROVENANCE_REJECTED` without erasing TOKEN state;
- maximum-field TOKEN size drops from r2's 876 bytes to 843 bytes before parents;
- a maximum-field TOKEN now fits four parents in the 1024-byte envelope;
- defined `REFERENCE_COVERS` separately from resolved causal ancestry;
- known-history reaffirmation now uses signed reference coverage;
- replaced r2 §35.2 migration/capacity contradiction with bounded linear reaffirmation folding;
- added durable `superseded-ID security record` and explicit remembered-head replacement so completed user intent survives later loss of an intermediate batch object without masking future loss of the new covering head;
- clarified that wide-frontier convergence is a linear fold, not a combinatorial merge search;
- updated DEVICE causality/presentation to use derived `DEVICE_ID`.

### v1/r2

Second v1 design draft.

Changes from r1:

- semantic object envelope reduced from 2048 to 1024 bytes;
- device provenance changed from strict deterministic Ed25519 to ECDSA P-256 with SHA-256;
- deterministic signing requirement removed;
- P-256 signer public key encoded as fixed 65-byte ANSI X9.63 uncompressed point;
- conforming writer signature encoded as DER ECDSA, with `1..72` byte field bound;
- TOKEN assertion validity separated from provenance verification;
- provenance status introduced: `VERIFIED`, `UNRESOLVED`, `REJECTED`;
- failed or malformed provenance no longer erases vault-authenticated TOKEN state;
- only provenance-verified DEVICE objects provide authenticated friendly names;
- bounded ordinary-TOKEN convergence batches added for frontiers/reaffirmations that cannot fit in one 1024-byte object.

### v1/r1

Initial v1 design draft.

Major differences from frozen v0:

- new protocol line and lowercase `totipo/v1/...` namespaces;
- `TOKEN_UPDATE` renamed to `TOKEN`;
- `DEVICE_UPDATE` renamed to `DEVICE`;
- all token state fields required in every `TOKEN`;
- complete token state directly authoritative;
- parent availability no longer gates token value validity;
- parent edges classified `RESOLVED`, `UNRESOLVED`, or `REJECTED`;
- ordinary conflict is whole-token value disagreement;
- no automatic disjoint-field composition;
- known accepted-head loss uses ordinary TOKEN reaffirmation;
- no recovery marker, generation ID, field CRDT, or lifecycle witness machinery.
