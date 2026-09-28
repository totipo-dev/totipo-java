# Totipo Vault Format v1

**Status:** design draft, revision 15  
**Protocol version:** 1  
**Revision:** r15  
**Scope:** encrypted append-only TOTP vault format, complete-state token assertions, token-local causal history, device presentation history, advisory local regression evidence, bootstrap semantics, cryptographic construction, canonical encoding, and writer/application safety.

**Historical note:** Earlier Totipo design work used a v0 draft. It was never released as an implemented/deployed protocol and is not a supported predecessor of v1. v1 defines no migration protocol from v0; historical v0 draft artifacts are outside the v1 protocol.

**Revision 15 summary:** v1/r15 intentionally simplifies state semantics: authenticated immutable objects over unreliable sync; accepted-snapshot authorship; optional advisory history; TOKEN-specific conflict confirmation; independent immutable publication. Strong local durability protects vault identity and private custody. No wire-format, crypto, routing-prefix, envelope-family, object-size, capacity-formula, TOTP algorithm, or identifier construction changes.

---

## 1. Goals

Totipo uses immutable authenticated objects and causal DAG semantics over an unreliable synchronization transport; strong local durability protects vault identity and private custody, while optional remembered history provides best-effort regression warnings rather than authoritative protocol state.

Totipo v1 is an encrypted, append-only, multi-device TOTP vault format intended for synchronization over an untrusted or partially trusted file-synchronization medium such as Syncthing, Dropbox, or Google Drive.

The principal goals are:

- small and auditable format and implementation surface;
- confidentiality against the synchronization medium;
- immutable authenticated content storage;
- deterministic synchronization-derived interpretation of the same observed object set;
- deterministic effective state given the same accepted authenticated snapshot;
- complete usable token state in every vault-authenticated TOKEN;
- explicit preservation of genuine concurrent disagreement;
- no silent field-wise synthesis of a state that no user confirmed;
- graceful availability when historical ancestry is missing;
- device provenance without a device-authorization system;
- best-effort local detection of previously observed history disappearing;
- efficient incremental synchronization;
- minimal externally visible semantic metadata.

v1 intentionally does not define:

- device authorization, enrollment, or revocation;
- global membership;
- protocol-level garbage collection;
- secure deletion;
- root-key rotation;
- traffic-analysis resistance;
- global consensus;
- a synchronized global vault frontier.

---

## 2. Object model

v1 defines two encrypted, content-addressed semantic object types:

```text
TOKEN
DEVICE
```

It additionally defines one non-content-addressed bootstrap record:

```text
VAULT
```

A `TOKEN` is one immutable vault-authenticated complete-state assertion concerning exactly one logical token.

A conforming `TOKEN` writer also attaches a device provenance claim:

```text
AUTHOR_DEVICE_ID
SIGNATURE
```

The corresponding P-256 public key is not repeated in every `TOKEN`.

A `DEVICE` carries:

- one canonical P-256 public key;
- a human-facing display name;
- a provenance signature made by that same key.

Define:

```text
DEVICE_ID =
    SHA-256(
        ASCII("totipo/v1/device-id")
        || PUBLIC_KEY_X963
    )
```

where `PUBLIC_KEY_X963` is the exact 65-byte ANSI X9.63 uncompressed P-256 representation:

```text
0x04 || X[32] || Y[32]
```

`DEVICE_ID` is 32 bytes.

A `TOKEN.AUTHOR_DEVICE_ID` refers to this derived identity. If no corresponding public key is currently available, the token value remains authoritative but its device provenance is unresolved.

Every `TOKEN` contains the complete token semantic state:

```text
TOKEN_ID
STATUS
ISSUER
ACCOUNT
CREDENTIAL
```

No token semantic field is inherited from parents.

Parent IDs express claimed causal incorporation. They are used for causality, convergence, and local reaffirmation; they are not required to reconstruct the complete token value.

A `DEVICE` affects presentation/provenance only. It never affects token value authority.

A client MAY maintain disposable indexes and materialized token views. All graph indexes are disposable derived state; optional history is advisory under Section 34.

## 3. Threat model

Totipo guarantees vault identity, cryptographic authenticity, immutable objects, causal interpretation, and explicit handling of known semantic conflicts. It does not guarantee synchronized-store completeness, propagation, freshness, rollback prevention, or transactionality.

### 3.1 Trusted local execution environment

The local kernel, filesystem implementation, mount/process namespace, and processes acting with the application's local privileges are trusted for baseline conformance. Immunity to an actively malicious same-privilege process racing individual pathname, file-type, directory-identity, or inode operations is optional hardening. Ordinary synchronization churn remains in scope. External synchronized bytes are hostile even when materialized on a local filesystem and MUST pass structural and cryptographic validation.

### 3.2 Authoritative local state

The durable local `VAULT_BINDING` pins the configured installation to accepted `K_root`. Private device-key custody is security-sensitive, private, crash-safe local state bound to that vault. Neither is an advisory cache.

### 3.3 Advisory local state

Optional remembered history supports regression warnings, startup indexes, and UI history. Loss or corruption of advisory history may reduce detection of unexpected regressions but does not invalidate otherwise authenticated current synchronized state.

### 3.4 Untrusted and unreliable synchronized transport

Synchronized storage is untrusted for content and unreliable for availability, propagation, completeness, and freshness. It may delay or omit objects, replay old subsets, later reveal hidden history, or remove previously visible objects. No local observation proves global completeness. No successful local publication proves peer propagation. No local scan proves another client has no newer object.

Without `K_root`, the synchronization-medium attacker cannot decrypt semantic contents, compute keyed IDs for guessed plaintext, construct new authenticated objects, or substitute another root without detection by an installation with an intact binding. Device signatures provide attribution, not authorization. Possession of `K_root` permits vault-valid state and a fresh provenance identity, but not forged verified attribution to an existing device key. A compromised unlocked client can read secrets and author valid history.

Valid concurrent forks are expected from offline operation, delayed sync, hidden history, ambiguous retries, and simultaneous clients. The DAG interprets them; storage transactions do not prevent them.

---

## 4. Storage model and envelope-family namespace

A v1 vault is stored conceptually as:

```text
vault

objects-v1/
    <OBJECT_ID>
    <OBJECT_ID>
    ...
```

`vault` is the mutable bootstrap record.

`objects-v1/` is the exact top-level object namespace for the **Totipo v1 envelope family**.

The `v1` in `objects-v1/` identifies the envelope/storage family, not merely `OBJECT_VERSION = 1`.

Inside `objects-v1/`:

- every protocol object file uses the v1-family filename grammar;
- every valid protocol object file is exactly 1024 bytes;
- every authenticated semantic object uses the v1-family object-ID/encryption construction;
- semantic versions may evolve through `OBJECT_VERSION` while preserving the frozen routing contract from Section 12.

The filename is the lowercase hexadecimal encoding of the 32-byte `OBJECT_ID`.

Only direct regular-file children of `objects-v1/` whose names consist of exactly 64 lowercase hexadecimal characters are v1-family object candidates.

Temporary files, synchronization-conflict copies, subdirectories, and unrelated filenames inside `objects-v1/` MUST be ignored by ordinary object discovery.

A v1 client MUST NOT recursively scan sibling namespaces such as:

```text
objects-v2/
objects-future/
anything-else/
```

for v1-family semantic objects.

The mere existence, name, size, or contents of an unknown sibling directory/file namespace is not authenticated semantic evidence and MUST NOT by itself create `OPAQUE_ROUTABLE`, `OPAQUE_UNSCOPED`, or a protocol warning/block.

Future envelope families may use different sibling namespaces and internal layouts.

`objects-v2/` is illustrative only; v1 does not freeze the internal layout or filename grammar of a future family.

One configured vault owns one synchronization root. Objects from different `K_root` values MUST NOT intentionally share the same `objects-v1/` namespace.

No v1 semantic information appears directly in the directory hierarchy below `objects-v1/`.

v1 does not define protocol garbage collection of valid historical v1-family objects.

Writers MUST publish complete immutable bytes with no overwrite of different existing bytes and atomic/complete visibility at the local filesystem API boundary (Section 50). Synchronized storage is an unreliable transport/cache, not a transactional database.

The atomic/no-replace requirement protects immutable publication and crash/concurrency correctness; it does not require defense against an already-compromised same-privilege local execution environment deliberately racing individual filesystem syscalls.

---

## 5. Cryptographic suite

v1 fixes the following primitives:

| Purpose | Primitive |
|---|---|
| Password KDF | Argon2id, version `0x13` |
| Root/subkey derivation | HKDF-SHA-256 |
| Private content addressing | HMAC-SHA-256 |
| Semantic object encryption | AES-256-GCM, 16-byte tag |
| Root-key wrapping | AES-256-GCM, 16-byte tag |
| Device provenance signatures | ECDSA over NIST P-256 (`secp256r1`) with SHA-256 |
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

P-256/SHA-256 is selected for broad native-platform support. A conforming implementation SHOULD use platform/JCA/CryptoKit/Keystore primitives rather than bundle independent elliptic-curve arithmetic merely for Totipo.

Hardware-backed signing keys are encouraged when available but are not required for interoperability.

## 6. Password bytes

The format password domain is exactly `0..1024` bytes of well-formed UTF-8. The empty UTF-8 byte string is format-valid.

A character/string password MUST be encoded to UTF-8 strictly. Encoding errors, including unpaired surrogate code units in APIs capable of representing them, MUST be rejected rather than replaced. Pre-encoded password bytes MUST be validated as well-formed UTF-8.

The protocol performs no Unicode normalization. Applications MUST NOT silently normalize, trim, case-fold, or otherwise transform password bytes before Argon2id.

Inputs longer than 1024 UTF-8 bytes MUST be rejected. Application policy MAY require a non-empty or stronger password for creation, but readers MUST remain able to process every format-valid password byte string.

A creation UI SHOULD warn or require explicit confirmation before creating a vault with an empty password. Applications MAY apply stronger local password policy at creation, but such policy MUST NOT make existing format-valid vaults unreadable.

---

## 7. Vault root key

At vault creation:

```text
K_root = CSPRNG(32 bytes)
```

`K_root` is the cryptographic identity of one v1 vault.

The password protects a wrapping of `K_root`; it is not itself the vault encryption key.

v1 does not support in-place `K_root` rotation. Changing `K_root` creates a new cryptographic vault.

If `K_root` is compromised, re-encrypting the same data under a new root does not undo prior disclosure. Credentials whose seeds may have been exposed SHOULD be rotated with their issuers.

---

## 8. VAULT bootstrap

The v1 `VAULT` record is a fixed 87-byte non-TLV structure:

```text
offset  size  field
0       10    MAGIC = ASCII("TOTIPO-VLT")
10       1    BOOTSTRAP_VERSION = 0x01
11      16    ARGON2_SALT
27      12    WRAP_NONCE
39      32    WRAPPED_ROOT
71      16    WRAP_TAG
-------------------------------
              total = 87 bytes
```

The authenticated clear bootstrap header is exactly bytes `0..38`:

```text
VAULT_HEADER =
    MAGIC
    || BOOTSTRAP_VERSION
    || ARGON2_SALT
    || WRAP_NONCE
```

On creation and password rewrap:

```text
ARGON2_SALT = CSPRNG(16)
WRAP_NONCE  = CSPRNG(12)
```

Derive `K_wrap` with the Section 5 Argon2id parameters, then:

```text
WRAPPED_ROOT, WRAP_TAG =
    AES-256-GCM(
        key       = K_wrap,
        nonce     = WRAP_NONCE,
        plaintext = K_root,
        AAD       = VAULT_HEADER,
        tag_len   = 16
    )
```

A reader MUST reject, before running Argon2id:

- any length other than exactly 87 bytes;
- magic other than exact ASCII `TOTIPO-VLT`;
- bootstrap version other than `0x01`;
- invalid password bytes under Section 6.

The `VAULT` record is an offline password verifier. Anyone possessing a copy may attempt local password guesses.

### 8.1 Initial publication

Ordinary initial creation is permitted only when the configured canonical `vault` pathname is absent and the location is not already locally established as another vault.

If candidate v1-family protocol object files already exist under `objects-v1/` while the canonical bootstrap is absent, ordinary creation MUST stop. The implementation MUST require explicit recovery/reconfiguration rather than create an unrelated vault over potentially recoverable v1-family material.

Initial bootstrap installation MUST use no-replace semantics or equivalent local exclusion and Section 9.1 durability. Authenticate the canonical VAULT and establish the local binding under Section 10 before reporting setup success. No pending binding record is required.

---

## 9. Password changes and crash-safe VAULT replacement

A password change rewraps the same `K_root`.

It does not change any semantic object.

A password change:

1. unlocks the established `K_root`;
2. generates a fresh 16-byte Argon2 salt;
3. derives `K_wrap` from the new password;
4. generates a fresh 12-byte wrapping nonce;
5. wraps the same `K_root`;
6. crash-safely replaces the canonical `vault` bootstrap.

Password rewrap does not revoke historical bootstrap copies. Anyone retaining an older valid bootstrap and its password may still recover the same `K_root`.

Concurrent unsynchronized password changes are not mergeable semantic operations.

### 9.1 Crash-safe VAULT publication

`vault` is the only intentionally mutable protocol pathname in v1.

Both initial creation and later password/bootstrap replacement MUST use crash-safe publication.

A conforming writer MUST construct complete bytes in a separate temporary file, flush/force that file, atomically install (initially no-replace) or replace the canonical pathname, and flush/force the containing directory. Platform-specific equivalent crash-safe mechanisms are acceptable. The intended root MUST remain unchanged on replacement. Under the trusted local environment this pattern requires neither repeated inode/path identity proofs nor mandatory rereads. A final cryptographic reopen MAY be used as defensive hardening and is recommended when practical.

Success requires completion of these durability steps and the authoritative local binding obligations. Interrupted or ambiguous authoritative-file publication is incomplete.

The canonical `vault` pathname MUST NOT be created or updated by truncating/overwriting the final file in place.

If the underlying platform cannot provide atomic installation/replacement semantics, the implementation MUST use the strongest available crash-safe mechanism and treat interrupted or ambiguous publication as incomplete.

Temporary files and provider/synchronization conflict copies are not authoritative bootstraps merely because they exist.

Only the single configured canonical `vault` pathname is automatically considered as the bootstrap candidate.

Files such as:

```text
vault.tmp
vault.sync-conflict-...
VAULT (conflicted copy ...)
```

or equivalent provider-generated alternate names MUST NOT be automatically interpreted as additional or alternate bootstraps.

A client MAY surface such files as evidence of synchronization conflict, but selecting/importing one requires explicit recovery/reconfiguration.

Crash-safe publication protects against torn local writes. It does not make concurrent password changes mergeable, prevent provider-side historical versions, or establish bootstrap freshness against rollback.

---

## 10. Durable local vault binding and establishment

Derive the unchanged local anchor:

```text
VAULT_BINDING =
    HMAC-SHA-256(
        K_root,
        ASCII("totipo/v1/local-vault-binding")
    )
```

`K_root` is uniformly random; this fixed domain separates the local PRF use. `VAULT_BINDING` is authoritative local state, independent of synchronized history.

Authenticate the configured canonical VAULT and derive the binding. If no binding exists, durably create it before ordinary use, semantic authorship, or creation/reuse of the configured device key. If a binding exists, require exact equality. A present but malformed/unreadable/corrupt binding is a local anchor failure requiring explicit recovery/reconfiguration; it MUST NOT silently become absence. A mismatching binding MUST reject automatic open and key reuse.

Use complete temporary bytes, file flush/force, atomic install/no-replace or replacement as appropriate, and containing-directory flush/force (or a platform equivalent). No journal or pending establishment record is required.

If canonical VAULT creation succeeded but the process crashes before binding creation, next startup behaves as first open for this installation: authenticate canonical VAULT and durably create the binding. This has fresh-installation limitations.

Device private-key storage MUST bind to this same vault, remain private under local permissions/platform custody, be crash-safe on creation, and prevent accidental replacement.

Password changes retain `K_root`. Historical same-root VAULT copies and their passwords remain usable. An optional `SHA-256(exact 87-byte VAULT representation)` fingerprint may warn of representation changes; it is audit evidence, not proof of rollback or a TOKEN gate.

---

## 11. Root-key hierarchy and v1 domains

After recovering `K_root`:

```text
PRK =
    HKDF-Extract(
        salt = 32 zero bytes,
        IKM  = K_root
    )
```

Derive:

```text
K_id =
    HKDF-Expand(
        PRK,
        ASCII("totipo/v1/object-id"),
        32
    )

K_object_root =
    HKDF-Expand(
        PRK,
        ASCII("totipo/v1/object-key-root"),
        32
    )

K_signature_context =
    HKDF-Expand(
        PRK,
        ASCII("totipo/v1/signature-context"),
        32
    )
```

The exact lowercase ASCII domain strings are protocol constants.

v1 additionally uses:

```text
totipo/v1/object-key
totipo/v1/object
totipo/v1/token
totipo/v1/device
totipo/v1/device-id
totipo/v1/local-vault-binding
```

Keys derived for different purposes MUST NOT be interchanged.

No v0 domain string is valid in v1.

---

## 12. Canonical semantic plaintext and frozen forward-compatible routing prefix

Every semantic object in the Totipo v1 envelope family has exact canonical semantic plaintext:

```text
P = CANONICAL_SEMANTIC_BYTES(object)
```

v1-family semantic objects live in `objects-v1/`.

The v1-family envelope contract includes:

```text
namespace       = objects-v1/
file size       = exactly 1024 bytes
object filename = 64 lowercase hex characters encoding OBJECT_ID
object-ID / key / nonce / AEAD construction = Sections 13–15
routing TLV framing and frozen routing fields = this section
```

These are envelope-family properties, not choices that a later `OBJECT_VERSION` may silently change.

v1 objects use the canonical TLV grammar in Sections 41–44.

The family freezes enough authenticated routing metadata for an older implementation to retain causal topology for a future semantic version even when it cannot interpret that version-specific body.

### 12.1 Common routing prefix

Every TOKEN and DEVICE semantic version that remains in `objects-v1/` begins with exactly:

```text
0001 OBJECT_VERSION u8
0002 OBJECT_TYPE    u8
0004 PARENT_COUNT   u16be
0005 PARENT_ID[32]  repeated PARENT_COUNT times, strictly increasing
0006 AUTHOR_TIME    u64be
```

using the same fixed TLV header framing as v1.

`PARENT_COUNT` remains syntactically bounded to `0..32`.

These fields and their order are frozen across semantic versions in the v1 envelope family.

### 12.2 TOKEN routing prefix

For `OBJECT_TYPE = TOKEN`, the common prefix is immediately followed by:

```text
0101 TOKEN_ID[32]
0102 AUTHOR_DEVICE_ID[32]
```

These fields and their order are frozen across TOKEN semantic versions in this envelope family.

Everything after the complete `0102 AUTHOR_DEVICE_ID` TLV is the version-specific TOKEN body.

A v1 reader parsing `OBJECT_VERSION != 1` MUST NOT interpret that body using the v1 TOKEN grammar.

### 12.3 DEVICE routing prefix

For `OBJECT_TYPE = DEVICE`, the common prefix is immediately followed by:

```text
0200 DEVICE_ID[32]
```

This field and its position are frozen across DEVICE semantic versions in this envelope family.

Everything after the complete `0200 DEVICE_ID` TLV is the version-specific DEVICE body.

For `OBJECT_VERSION = 1`, Section 20 additionally requires:

```text
DEVICE_ID =
    SHA-256(
        ASCII("totipo/v1/device-id")
        || PUBLIC_KEY_X963
    )
```

A future DEVICE semantic version may change its presentation/key body semantics while preserving the stable routing identity.

### 12.4 Opaque compatibility classes

After successful authentication of an exact 1024-byte candidate from `objects-v1/` and keyed object-ID verification, a reader classifies semantic bytes as one of:

```text
SUPPORTED_VALID
OPAQUE_ROUTABLE
OPAQUE_UNSCOPED
INVALID
```

`SUPPORTED_VALID` means the implementation understands the complete semantic version and the object passes that version's intrinsic grammar.

`OPAQUE_ROUTABLE` means the semantic version is unsupported, `OBJECT_TYPE` is TOKEN or DEVICE, and the complete frozen routing prefix for that type is structurally valid. The version-specific tail is not interpreted.

`OPAQUE_UNSCOPED` means an **authenticated v1-family semantic object** cannot be safely associated with a known TOKEN/DEVICE logical identity by this implementation, including an unknown object type or an unsupported semantic version that does not preserve the applicable frozen routing prefix.

A differently sized file in `objects-v1/` is not authenticated future-version evidence because it cannot satisfy the v1-family envelope contract.

An unknown sibling family namespace is likewise not authenticated semantic evidence.

`INVALID` means a semantic version/type the implementation claims to support fails that supported grammar or cryptographic/intrinsic checks.

### 12.5 Future semantic version versus future envelope family

A future semantic version may remain in `objects-v1/` only if it preserves the complete v1-family envelope contract.

If a future design needs a different object file size, variable-size objects, another object-ID/encryption construction, incompatible routing framing, or another storage/file-layout model, then it is a **different envelope/storage family**, not merely a new `OBJECT_VERSION` inside `objects-v1/`.

A future family is expected to use a separate sibling storage namespace defined by that future specification.

### 12.6 Rolling compatibility across envelope families

A future envelope family that claims rolling-upgrade interoperability with v1 MUST maintain a v1-family compatibility projection in `objects-v1/` for semantic state changes that older v1 clients need to observe.

Such compatibility state is represented using ordinary authenticated v1-family objects:

- if the future state is exactly representable as supported v1 semantics, the future client MAY publish an ordinary supported v1 TOKEN/DEVICE;
- otherwise it publishes an appropriate future `OBJECT_VERSION` in the v1 envelope family whose frozen routing metadata makes it `OPAQUE_ROUTABLE` to old clients.

The old v1 client does not need to understand or locate the corresponding future-family object.

The compatibility object's opaque tail may contain future-family metadata understood by newer clients, but v1 ignores that tail.

A future-family writer claiming rolling compatibility MUST ensure the required v1-family compatibility assertion receives local immutable-publication acknowledgement no later than it reports the corresponding future-family semantic action successful.

If a compatibility frontier is too wide for one v1-family object, the future specification must preserve equivalent causal coverage using bounded v1-family compatibility objects.

Rolling-upgrade interoperability with v1 is cooperative, not enforceable by v1 alone: an older v1 client can observe future-family state only to the extent that the future-family writer publishes the required authenticated v1-family compatibility projection.
A future envelope family that does not publish such compatibility state makes no rolling-upgrade compatibility promise to v1 clients.

### 12.7 Compatibility boundary

Directory names of unknown sibling families are organizational/storage information only.

They are not trusted downgrade/future-version signals.

An old v1 client learns security-relevant future state only through authenticated evidence inside `objects-v1/`.

This prevents an untrusted synchronization provider from creating warnings or authoritative-operation blocks merely by inventing `objects-v999/` or differently sized junk files.

---

## 13. OBJECT_ID

For exact canonical semantic plaintext `P`:

```text
OBJECT_ID =
    HMAC-SHA-256(
        K_id,
        P
    )
```

`OBJECT_ID` is exactly 32 bytes. It is deterministic within one vault, private to that vault, content-addressed, and unsuitable for offline plaintext guessing without `K_id`.

---

## 14. Fixed semantic-object encryption envelope

v1 uses one fixed 1024-byte semantic-object file.

For `OBJECT_ID = ID`:

```text
K_object =
    HKDF-Expand(
        K_object_root,
        ASCII("totipo/v1/object-key") || ID,
        32
    )

nonce = first 12 bytes of ID

AAD =
    ASCII("totipo/v1/object")
    || ID
```

Let `P` be the canonical semantic plaintext including the provenance-signature field.

Construct:

```text
ENCRYPTION_PLAINTEXT =
    SEMANTIC_LENGTH_U16BE
    || P
    || ZERO_PADDING
```

where:

- `SEMANTIC_LENGTH_U16BE` is exactly 2 bytes;
- the encryption plaintext is exactly 1008 bytes;
- semantic capacity is exactly 1006 bytes;
- every padding byte is zero.

Encrypt with AES-256-GCM and a 16-byte tag. The final object file is exactly 1024 bytes.

No random or alternate padding is permitted.

The construction order is:

```text
canonical semantic plaintext
        ↓
OBJECT_ID
        ↓
fixed canonical zero-padded envelope
        ↓
per-object key from full OBJECT_ID
        ↓
nonce from OBJECT_ID
        ↓
AES-GCM
```

A 1024-byte envelope intentionally trades some maximum one-object parent fan-in for half the synchronized bytes of r1's 2048-byte envelope. Sections 45 and 47 define bounded multi-object convergence when a complete frontier cannot fit in one object.

## 15. v1-family object reading and future-semantic dispatch

v1 ordinary discovery considers only direct object candidates under:

```text
objects-v1/
```

Given candidate filename `ID`, a reader:

1. requires exact 64-character lowercase hex and decodes 32 raw ID bytes;
2. requires exactly 1024 object bytes before AEAD processing;
3. derives the v1-family object key and nonce from `ID`;
4. authenticates/decrypts the fixed envelope;
5. reads authenticated `SEMANTIC_LENGTH_U16BE`;
6. requires the semantic length to fit;
7. extracts exactly that many semantic bytes;
8. requires all remaining padding bytes to be zero;
9. recomputes the keyed object ID over the exact semantic bytes and requires equality with the filename;
10. parses the frozen routing prefix as far as the declared object type requires;
11. dispatches by semantic version and object type.

For `OBJECT_VERSION = 1` and a supported v1 type, the complete v1 grammar applies.

For an unsupported semantic version inside the v1 envelope family, a structurally valid frozen TOKEN/DEVICE routing prefix yields `OPAQUE_ROUTABLE`; the remaining semantic tail is not parsed as v1.

An authenticated unknown object type or incompatible future routing prefix inside a valid v1-family envelope yields `OPAQUE_UNSCOPED`.

A candidate in `objects-v1/` with any file length other than exactly 1024 bytes is invalid current v1-family storage evidence.

It MUST NOT by itself create `OPAQUE_ROUTABLE` or `OPAQUE_UNSCOPED`, because no authenticated v1-family envelope has been established.

Likewise, files under unknown sibling namespaces are outside v1-family object discovery and do not enter this classification pipeline.

---

## 16. Device identity and P-256 provenance profile

A device provenance key is an ECDSA signing key on NIST P-256 (`secp256r1`).

Its canonical public-key bytes are exactly the 65-byte ANSI X9.63 uncompressed representation:

```text
PUBLIC_KEY_X963 =
    0x04 || X[32] || Y[32]
```

where `X` and `Y` are unsigned 32-byte big-endian field coordinates.

The 32-byte logical device identity is:

```text
DEVICE_ID =
    SHA-256(
        ASCII("totipo/v1/device-id")
        || PUBLIC_KEY_X963
    )
```

A conforming device SHOULD generate a distinct P-256 signing key pair for each vault.

Device keys provide provenance, not protocol authorization.

A conforming writer signs using ECDSA over P-256 with SHA-256.

The intended native mappings are:

```text
Java / JCA:
    SHA256withECDSA + secp256r1

Android:
    Android Keystore EC/secp256r1 + SHA256withECDSA

Apple:
    CryptoKit P256.Signing
    Secure Enclave P256.Signing where supported/desired
```

Implementations SHOULD use platform/native cryptographic signing implementations rather than bundle independent elliptic-curve arithmetic merely for Totipo.

ECDSA signing MUST use a signing implementation with cryptographically secure ephemeral-scalar (`k`) generation. A trusted implementation may derive `k` deterministically, for example using RFC 6979, or generate it from a platform CSPRNG with appropriate entropy. Deterministic RFC 6979 signing is acceptable and SHOULD be preferred when it is directly provided by the selected trusted platform/library API. Implementations MUST NOT add ad-hoc nonce-generation logic merely for Totipo.

ECDSA signatures need not be deterministic. Randomized signatures from a secure native/platform implementation are valid and expected.

If an implementation detects the same ECDSA `r` value in distinct signatures made by the same provenance key, it SHOULD surface a provenance-key compromise/anomaly warning. Such a diagnostic does not retroactively change TOKEN value authority.

A conforming writer emits the signature as canonical DER ECDSA `(r,s)` bytes. For P-256 the field is bounded to `0..72` bytes; a zero-length signature is an explicit no-valid-signature representation and yields rejected provenance.

High-S and low-S mathematically valid ECDSA signatures are both acceptable. v1 does not use signature normalization as semantic identity.

Provenance-verifier differences MUST NOT change `TOKEN` value authority.

### 16.1 Public-key availability for TOKEN provenance

A verifier may obtain the P-256 public key for `AUTHOR_DEVICE_ID` from:

- an `ASSERTION_VALID DEVICE` whose derived `DEVICE_ID` matches;
- an optionally retained authenticated DEVICE/key copy (not a current graph node);
- locally bound key material for the same established vault.

An implementation MAY retain exact authenticated public-key material for future provenance verification. Retention does not make the DEVICE a current presentation head.

The `DEVICE` object's own friendly-name provenance signature need not verify in order for its exact structurally valid public-key bytes to be retained as candidate verification material for a TOKEN. The TOKEN signature independently proves possession of the corresponding private key.

If no matching public-key bytes are available in accepted synchronized data, optional authenticated copies, or locally bound key material, TOKEN provenance is `UNRESOLVED`.

If matching public-key bytes are available but do not decode as P-256, or the TOKEN signature fails, TOKEN provenance is `REJECTED`.

If the signature verifies, TOKEN provenance is `VERIFIED`.

Whenever matching public-key material for a known `AUTHOR_DEVICE_ID` becomes newly available — for example because a matching DEVICE advertisement arrives, a retained DEVICE record is restored, or locally bound key material becomes available — the implementation MUST recompute provenance status for affected known TOKEN assertions.

This re-evaluation may transition provenance:

```text
UNRESOLVED -> VERIFIED
UNRESOLVED -> REJECTED
```

depending on the newly available key material and signature result.

Provenance re-evaluation MUST NOT change:

- TOKEN assertion validity;
- `TOKEN_VALUE`;
- causal ancestry/current-head calculation;
- credential authority.

It changes only attribution/provenance state and associated UI.

A SHA-256 collision causing two distinct canonical public keys to share one `DEVICE_ID` is outside the ordinary threat model. If an implementation ever observes distinct public-key byte strings for one `DEVICE_ID`, it MUST treat provenance for that identity as rejected/anomalous rather than choose one.

### 16.2 Initial DEVICE advertisement

Before reporting first TOKEN setup success for local device D, the matching assertion-valid, correctly self-signed locally authored DEVICE for D MUST have received local immutable-publication acknowledgement (`PUBLISHED_NEW` or `ALREADY_PRESENT_EXACT` equivalent), and the TOKEN publication must also be acknowledged. Wrong-key or invalid DEVICE assertions do not satisfy this prerequisite. TOKEN-before-DEVICE publication is allowed if success is withheld until both acknowledgements.

This ensures the writer attempted to place the public key into synchronized storage before reporting setup complete; it does not prove any peer has received it. Later DEVICE disappearance may leave remote TOKEN provenance `UNRESOLVED` without retroactively invalidating TOKEN state. No durable local graph record is required. Runtime self-reverification is optional hardening; writers MUST generate correct canonical self-signed bytes.

---

## 17. TOKEN_ID

Every newly created logical token receives:

```text
TOKEN_ID = CSPRNG(32 bytes)
```

A `TOKEN_ID` has no semantic meaning, is never intentionally reused for another logical token, and remains constant across all `TOKEN` assertions for that logical token.

Independent roots using the same `TOKEN_ID` are not automatically invalid. They are concurrent assertions for the same logical token.

Honest accidental collision is cryptographically negligible. A client SHOULD surface multiple independent roots for one `TOKEN_ID` as anomalous provenance even when their complete values agree.

---

## 18. TOKEN

A v1 `TOKEN` is an immutable vault-authenticated complete-state assertion for exactly one logical token.

```text
TOKEN {
    // frozen TOKEN routing prefix
    OBJECT_VERSION = 1
    OBJECT_TYPE    = TOKEN
    PARENT_COUNT
    PARENT_ID[...]
    AUTHOR_TIME[8]
    TOKEN_ID[32]
    AUTHOR_DEVICE_ID[32]

    // v1-specific TOKEN body
    STATUS = LIVE | TOMBSTONE
    ISSUER
    ACCOUNT
    CREDENTIAL {
        ALGORITHM
        DIGITS
        PERIOD
        SECRET_BYTES
    }
    SIGNATURE[0..72]
}
```

Every v1 token semantic state field is required.

`TOKEN_ID` and `AUTHOR_DEVICE_ID` are part of the frozen forward-compatible TOKEN routing prefix.

`AUTHOR_DEVICE_ID`, `AUTHOR_TIME`, and `SIGNATURE` are provenance/presentation metadata and do not participate in `TOKEN_VALUE`.

```text
TOKEN_VALUE(C) =
    (
        C.STATUS,
        C.ISSUER,
        C.ACCOUNT,
        C.CREDENTIAL
    )
```

Two supported v1 TOKENs with equal `TOKEN_VALUE` remain semantically equal even when authors, signatures, parents, IDs, or `AUTHOR_TIME` differ.

A parentless v1 TOKEN is a root assertion.

A conforming writer creating a new logical token uses a fresh random `TOKEN_ID`, no parents, its local `DEVICE_ID` as `AUTHOR_DEVICE_ID`, one Section 20.1 `AUTHOR_TIME`, and a correct provenance signature.

---

## 19. Semantic-object provenance signatures

A conforming `TOKEN` writer signs:

```text
ASCII("totipo/v1/token")
||
K_signature_context
||
canonical_unsigned_token
```

using ECDSA P-256 with SHA-256.

A conforming `DEVICE` writer signs:

```text
ASCII("totipo/v1/device")
||
K_signature_context
||
canonical_unsigned_device
```

using ECDSA P-256 with SHA-256.

The canonical unsigned object is the canonical semantic object with the complete `SIGNATURE` TLV omitted.

`K_signature_context` is intentionally part of the signed message even though `DEVICE_ID` is vault-independent. It binds provenance to one vault root: the same device public key and otherwise identical unsigned semantic bytes produce a different signature input in a different vault. Without this vault-derived context, a valid provenance signature copied from one vault could verify in another vault that knows the same public key, incorrectly carrying device attribution across vault boundaries.

The ASCII object-type prefixes additionally separate TOKEN and DEVICE provenance-signature domains.

Writer construction order:

```text
build canonical unsigned object
        ↓
construct object-specific signature input
        ↓
platform ECDSA-P256/SHA-256 signing
        ↓
encode signature as DER
        ↓
insert SIGNATURE
        ↓
canonical semantic plaintext
        ↓
compute OBJECT_ID
        ↓
encrypt
```

Because ECDSA signing may be randomized, two otherwise identical actions may produce distinct signatures and object IDs. This is acceptable.

A conforming writer MUST locally verify its newly generated signature before publishing.

Readers classify provenance independently from state assertion validity under Section 21.

A `TOKEN` signature is verified against public-key material whose derived `DEVICE_ID` equals `AUTHOR_DEVICE_ID`.

A `DEVICE` signature is self-verified against the `PUBLIC_KEY_X963` contained in that `DEVICE`.

---

## 20. DEVICE

A v1 `DEVICE` is an immutable vault-authenticated presentation and public-key advertisement object.

```text
DEVICE {
    // frozen DEVICE routing prefix
    OBJECT_VERSION = 1
    OBJECT_TYPE    = DEVICE
    PARENT_COUNT
    PARENT_ID[...]
    AUTHOR_TIME[8]
    DEVICE_ID[32]

    // v1-specific DEVICE body
    PUBLIC_KEY_X963[65]
    DISPLAY_NAME
    SIGNATURE[0..72]
}
```

For v1:

```text
DEVICE_ID = SHA-256(
    ASCII("totipo/v1/device-id")
    || PUBLIC_KEY_X963
)
```

The serialized `DEVICE_ID` MUST equal that derivation exactly.

Explicit serialization lets an older client retain a future DEVICE's causal identity even if that future version changes its key/presentation body format.

DEVICE does not affect token value authority or token causality.

Only a provenance-verified supported DEVICE may provide an authenticated friendly name.

An assertion-valid v1 DEVICE with unresolved/rejected DEVICE provenance may still supply its structurally valid public key as candidate verification material for TOKEN provenance; the TOKEN signature independently decides possession of the corresponding private key.

### 20.1 Common informational AUTHOR_TIME

Every TOKEN and DEVICE semantic version in this envelope family carries:

```text
AUTHOR_TIME = u64be Unix seconds
```

`0` means unknown.

Readers preserve the full unsigned value/raw 8 bytes and accept every `u64`, including values outside platform date ranges.

`AUTHOR_TIME` is authenticated routing/presentation metadata only.

It MUST NOT be used for causal ordering, parent resolution, head selection, conflict resolution, freshness/rollback, “newest wins,” object validity, or automatic credential choice.

UI SHOULD label it reported/device-reported time.

For one multi-object fold, all objects representing that one confirmed action use one captured `AUTHOR_TIME`.

---

## 21. Intrinsic semantic assertion validity and provenance status

v1 deliberately separates:

```text
ASSERTION_STATUS
PROVENANCE_STATUS
PARENT_EDGE_STATUS
```

### 21.1 ASSERTION_STATUS

A supported-version `TOKEN` or `DEVICE` is `ASSERTION_VALID` when all checks intrinsic to its vault-authenticated semantic bytes and complete state grammar succeed.

Intrinsic checks include at least:

- canonical envelope and zero padding;
- object-ID equality;
- canonical TLV framing and ordering;
- correct object version and type;
- exact parent count/repetition framing;
- strictly increasing raw parent IDs;
- valid UTF-8 and token field limits;
- complete required TOKEN state fields;
- valid token enums/ranges;
- required provenance TLVs are structurally present;
- `AUTHOR_TIME` is exactly 8 bytes in both TOKEN and DEVICE;
- `TOKEN.AUTHOR_DEVICE_ID` is exactly 32 bytes;
- `DEVICE.DEVICE_ID` is exactly 32 bytes;
- `DEVICE.PUBLIC_KEY_X963` is exactly 65 bytes;
- v1 `DEVICE_ID` exactly equals the Section 20 derivation from `PUBLIC_KEY_X963`;
- `SIGNATURE` length is in `0..72`.

The following are **not** assertion-validity requirements:

- `DEVICE.PUBLIC_KEY_X963` decodes to a valid curve point;
- a matching public key for `TOKEN.AUTHOR_DEVICE_ID` is currently available;
- the signature bytes decode as DER;
- the signature verifies;
- every named parent currently exists;
- every named parent eventually proves valid;
- every named parent has the expected semantic type;
- every named token parent concerns the same `TOKEN_ID`;
- every named device parent concerns the same derived `DEVICE_ID`;
- the listed parent set is retrospectively an ancestry antichain.

A defect in the authenticated complete TOKEN state makes the assertion invalid.

A defect confined to provenance verification or parent semantics does not erase an otherwise valid complete TOKEN value.

### 21.2 PROVENANCE_STATUS

For every `ASSERTION_VALID TOKEN` or `DEVICE`, provenance is independently classified:

```text
VERIFIED
UNRESOLVED
REJECTED
```

For a `TOKEN`:

`VERIFIED` means matching P-256 public-key bytes are available for `AUTHOR_DEVICE_ID` and the DER ECDSA/SHA-256 signature verifies over the exact Section 19 input.

`UNRESOLVED` means no matching verification public key is currently available, or a temporary local resource condition prevents verification.

`REJECTED` means candidate key material is available but invalid, the signature is zero-length/malformed, or ECDSA verification fails.

All three provenance states retain the same TOKEN value authority.

Only `VERIFIED` provenance may be attributed to the claimed device identity.

A current TOKEN with `REJECTED` provenance SHOULD produce a prominent warning and SHOULD offer user reaffirmation by an ordinary locally provenance-verified child TOKEN. Reaffirmation is not a different wire object.

For a `DEVICE`:

`VERIFIED` means `PUBLIC_KEY_X963` decodes as P-256 and its self-signature verifies.

`UNRESOLVED` is reserved for temporary local inability to complete verification.

`REJECTED` means the public key is not a valid P-256 point, the signature is zero-length/malformed, or verification fails.

Only `PROVENANCE_VERIFIED DEVICE` objects participate in authenticated friendly-name presentation.

Unverified or rejected `DEVICE` objects remain vault-authenticated audit/key-advertisement material.

A provenance signature is attribution evidence, not a membership credential and not the authority source for TOKEN state.

## 22. Authenticated parent claims and graph integrity

Supported-valid and opaque-routable objects contain immutable authenticated parent claims. Evaluate them within the accepted snapshot. A TOKEN edge resolves to an accepted supported-valid or opaque-routable TOKEN with the same TOKEN_ID; a DEVICE edge resolves analogously for DEVICE_ID. An accepted object at the exact ID with wrong type/identity rejects the edge. Missing, unreadable, cryptographically invalid, or intrinsically invalid parent evidence leaves the edge unresolved. Neither unresolved nor rejected edges invalidate the complete child or suppress another head.

Resolved graphs MUST be acyclic. Two genuinely different authenticated meanings at one OBJECT_ID violate the cryptographic/global identity invariant. A resolved cycle or such contradiction MUST fail evaluation safely and abort use of that inconsistent snapshot/vault context. Neither is ordinary semantic conflict. No permanent sticky cache flag is required after restart; malformed optional cache data is discarded under Section 34.

---

## 23. Accepted ancestry and concurrency

For accepted TOKEN nodes A and B with the same TOKEN_ID, `A <c B` iff a resolved parent path leads from B to A. Two nodes are concurrent when neither is in the other's ancestry. The analogous DEVICE relation uses same-DEVICE_ID edges.

Semantic version, device identity, arrival order, filename order, AUTHOR_TIME, provenance, and value equality never create ordering. Missing intermediate objects may prevent resolving a path in this snapshot; advisory remembered topology MUST NOT silently supply that path.

---

## 24. Accepted snapshot, discovery, and current frontier

`ACCEPTED_SNAPSHOT` is the set of objects this client has successfully read, envelope-authenticated, keyed-ID authenticated, routed/classified, and semantically accepted as appropriate from one local observation context, plus locally authored objects successfully published during the current process as appropriate. A snapshot is local evidence, not proof of global completeness. A writer acts on an accepted local snapshot.

### 24.1 Current graph

Current TOKEN/DEVICE graphs derive solely from accepted object evidence in that snapshot. Implementations MAY cache indexes; indexes are disposable derived state, not a separate durable protocol authority. An advisory history entry MUST NOT make an object currently present merely because it was seen previously. Explicitly selected authenticated historical copies can support candidate/history use; they do not silently supplement current heads.

### 24.2 Diagnostics

A snapshot MAY carry diagnostics for incomplete enumeration, unreadable candidates, resource limits, missing remembered history, and authenticated unknown/future evidence. These diagnostics do not automatically make accepted objects invalid or block ordinary operations. Implementations SHOULD disclose known incomplete-view, regression, memory-loss, and compatibility warnings. Exact UI words are non-normative.

### 24.3 Discovery completeness

`PROCESSING_INCOMPLETE` means the client did not successfully process every locally observed candidate. Enumeration failure, unavailable required bytes, and exhausted resources MUST NOT become implicit validity. Successfully accepted objects remain usable. The client MUST disclose that its local view may be incomplete. A complete local pass means every locally observed candidate received a terminal classification, not that remote history is complete. Implementations MAY conservatively wait/retry; v1 does not require a vault-wide operation gate.

### 24.4 Current TOKEN heads

`CURRENT_TOKEN_HEADS(T, S)` is the set of maximal accepted supported-valid and opaque-routable TOKEN nodes for T under resolved ancestry in S. Opaque-unscoped evidence has no assignable TOKEN scope and is not a TOKEN head.

### 24.5 Current values

An opaque-routable current TOKEN head makes that TOKEN's semantic state incomplete/unknown and blocks ordinary use and v1 semantic authorship for T. Otherwise accepted supported heads supply complete TokenValue alternatives. One distinct value is unambiguous; multiple distinct values are a known whole-state conflict. No heads means no current value (new-token creation is separate).

### 24.6 Reappearance and corruption

Absence/unreadability says only “not available in this accepted local observation”; it proves neither global deletion/nonexistence nor rollback nor invalidity of earlier authored history. Wrong length, AEAD failure, padding failure, and keyed-ID failure are invalid/unavailable local evidence, never authenticated opaque evidence. Remembered facts may support regression warnings but cannot authenticate corrupt current bytes. Later valid reappearance is evaluated normally and may reveal concurrency.

---

## 25. Whole-state value and completeness semantics

For token T in accepted snapshot S, let H = CURRENT_TOKEN_HEADS(T, S), O be the opaque-routable subset of H, and V be the distinct complete supported TOKEN_VALUEs in H (Section 18).

```text
H empty: no current TOKEN state
O non-empty: VALUE_INCOMPLETE_OPAQUE
O empty and |V| == 1: semantically unambiguous
O empty and |V| > 1: whole-state conflict
```

Every accepted supported current object supplies its complete value. A remembered but absent object is not in H. An implementation unable to retain/read required accepted value evidence must obtain it again or evaluate a subsequent observation without that object; it must not invent a usable value. Opaque current state prevents claiming complete understanding even when supported values agree. Semantic-version number never orders state.

---

## 26. Lazy convergence

If every current TOKEN head is supported/readable and all complete values are equal, the client may leave the multi-head frontier unchanged.

A later meaningful edit naturally parents the full current frontier.

If any current head is opaque, v1 MUST NOT author merely to collapse the frontier.

A client that understands the opaque semantics may later author a descendant.

If a v1 client later learns a supported-readable descendant of the opaque node and all current heads become supported/readable, ordinary v1 semantics may resume.

---

## 27. Visible whole-state conflict and semantic confirmation

When accepted current supported heads for T contain multiple distinct complete TokenValue alternatives, ordinary use/authorship MUST remain conflict-sensitive. Publishing one resulting complete state requires explicit user confirmation; clients MUST NOT silently merge fields. Confirmation may choose one existing complete value or a newly composed complete value.

Bind confirmation to at least TOKEN_ID, exact visible supported head set H, exact visible complete TokenValue alternatives, exact desired complete TokenValue, and relevant operation intent. Immediately before publication, recompute this TOKEN-specific semantic context from the latest accepted observations. If it changed, obtain renewed confirmation. Newly learned TOKEN-relevant semantic information material to what the user saw also requires reconfirmation, even if a later event restores an earlier-looking context. This event sensitivity is limited to the semantic decision.

Unrelated TOKEN changes, DEVICE display presentation, provenance-only changes, discovery events, sibling files, and generic vault owner revisions do not stale confirmation. There is no vault-global consent epoch. The recheck keeps the human decision aligned with known conflict; it cannot exclude hidden remote history.

Previously remembered but currently absent objects are not current H. Regression evidence SHOULD warn and MAY prompt additional product-policy confirmation, but unavailable remembered history does not mandate Section 27 confirmation.

---

## 28. Hidden or later-discovered history

Later discovery of history that was not present in the accepted snapshot may make a prior locally authored object concurrent with that history. This does not retroactively invalidate the authored object.

```text
accepted snapshot: A
writer plans:      B parent A
before or after B publication another client object appears: C parent A

    A
   / \
  B   C
```

B and C are ordinary concurrent history. Neither publication is invalid merely because the other was not observed. Different complete values create conflict; equal values remain unambiguous. No rollback of B is required. A client may act only on what it has authenticated, but it cannot infer that authenticated hidden history does not exist.

---

## 29. Missing ancestry and remembered history

A supported TOKEN with an unavailable parent still contains a complete authenticated value. It can be current and ordinarily usable despite unresolved ancestry. Signed parent claims remain part of its immutable bytes; a missing parent does not turn the child into a root.

An absent remembered object is not a current head. If current accepted evidence fails to causally incorporate remembered history, Section 34 recommends a regression warning. An older available assertion can be current in this snapshot; the warning communicates the missing historical evidence. Later arrival can resolve ancestry or reveal conflict. An opaque current head is different: it is accepted current evidence with semantics this client cannot interpret.

---

## 30. Delete, restore, and credential changes

`STATUS` is `LIVE` or `TOMBSTONE`.

Every tombstoned `TOKEN` still contains complete `ISSUER`, `ACCOUNT`, and `CREDENTIAL` fields. Deletion is logical state, not secure erasure.

A conforming application SHOULD hide an unambiguously tombstoned token from ordinary active-token views while retaining history/recovery discoverability.

A transition from an unambiguous known current `TOMBSTONE` state to `LIVE` is a restoration action and SHOULD require explicit user intent appropriate to restoration.

Credential rotation creates an ordinary complete `TOKEN`.

If deletion/restoration races with another edit, the resulting complete states differ and the normal whole-state conflict workflow applies.

The protocol MUST NOT field-merge a tombstoned old credential and a concurrent live new credential into a synthesized state.

This whole-state rule replaces v0's lifecycle-witness machinery.


---

## 31. DEVICE presentation graph

Accepted DEVICE topology includes supported-valid and opaque-routable nodes.

Current DEVICE heads for one `DEVICE_ID` are maximal accepted nodes under resolved same-device ancestry, regardless of provenance status.

Only supported provenance-`VERIFIED` DEVICE heads may supply authenticated friendly names.

Supported current DEVICE heads with provenance `UNRESOLVED` or `REJECTED` are **presentation-inert**: they do not supply an authenticated friendly name and are not counted as authenticated-name alternatives. They remain causal graph heads and MUST still be incorporated by a conforming rename/convergence operation under Section 49.

If at least one supported readable provenance-verified current head exists and all such heads agree on one name, that name is the authenticated current presentation even when additional supported unverified/rejected heads exist; the UI SHOULD separately surface provenance warnings for those inert heads.

If verified supported current heads provide differing readable names, presentation is conflicted.

If any current DEVICE head is opaque, presentation state is incomplete for v1. The client SHOULD fall back to `DEVICE_ID` / known key fingerprint plus a future-version presentation warning rather than presenting a previously readable historical name as confidently current.

A later supported v1 DEVICE descendant may restore readable current presentation.

Opaque or unverified DEVICE state affects presentation/provenance only and MUST NOT invalidate TOKEN state authority or credential generation.

---

## 32. Snapshot-based writer parent rule

For ordinary TOKEN authorship:

```text
S = accepted snapshot used for the operation
H = CURRENT_TOKEN_HEADS(T, S)
PARENTS(new) = H
```

The exact parent set attests “these were the current TOKEN heads the writer had accepted when it planned this operation.” It does not attest global completeness, absence of concurrent remote history, or that H remained the local frontier until publication.

Ordinary updates require one complete understood semantic value in S for T. Creation of a new TOKEN uses empty H. A known visible supported conflict requires Section 27 confirmation. An opaque current TOKEN head blocks semantic authorship for T, not unrelated tokens. A writer MUST NOT drop required parents merely to fit; Section 47 folds cover wide frontiers.

---

## 33. Operations against accepted snapshots

Ordinary use and authorship operate against an explicitly accepted local snapshot. There is no required last-moment frontier linearization for ordinary writes. History arriving after planning may be concurrent and does not invalidate the planned object. Implementations MAY conservatively restart; conformance does not require it.

Changes to another TOKEN, DEVICE presentation, unrelated availability/provenance, or sibling files do not retroactively invalidate ordinary writes. Only human conflict-resolution confirmation has the TOKEN-specific semantic recheck in Section 27.

Ordinary TOTP use requires accepted supported current state, no opaque current TOKEN head, complete supported values, and exactly one distinct LIVE TokenValue. Explicit candidate use pins the selected authenticated readable supported LIVE object and value with Section 35 warnings. Neither requires cache health, globally complete discovery, or absence of unrelated unscoped evidence.

---

## 34. Advisory local history

Implementations MAY retain advisory local history: previously accepted OBJECT_IDs, routing summaries, head sets, or optional authenticated object copies. Its purposes are regression detection, startup acceleration, diagnostics, and UI history. Advisory history MUST NOT become authoritative current protocol state or silently add current objects, readable values, or ancestry.

Advisory remembered history is an optional local capability. Baseline Totipo v1/r15 implementations derive protocol state solely from accepted authenticated snapshots and need not retain cross-run graph history. Implementations without advisory history remain baseline conforming and are not required to emit history-derived warnings. The mere absence of an advisory-history feature is not HISTORY_MEMORY_LOST. Such clients cannot detect regressions based on observations from earlier executions.

Implementations may use an atomic snapshot file, database, preferences, or no cache. No append-only journal, frame format, replay, tail repair, ambiguous-append poison, exact retained bytes, or persistence representation is required. Cache durability is advisory/best effort; atomic replacement with file/directory flushes can improve reliability.

An implementation that retains advisory history SHOULD use it to detect regressions or history-memory loss as described below. These diagnostics apply only to retained/expected advisory state or detected cache failures; they are not serialized consensus/protocol states:

- `HISTORY_NORMAL`: no regression detected from available remembered evidence; not a freshness proof.
- `HISTORY_REGRESSION`: current accepted evidence does not causally incorporate some previously remembered history. It reports apparent regression/stale view. Ordinary reading and TOKEN authorship are not automatically blocked. Reappearance may reveal conflict after a write.
- `HISTORY_MEMORY_LOST`: meaningful evidence indicates that history previously retained or expected by this implementation is absent, unreadable, malformed, deleted, or restored inconsistently. Discard/ignore it, rebuild from accepted synchronized objects, and continue. Intentional nonimplementation of the feature does not qualify; no sticky protocol failure results.
- `HISTORY_CACHE_WRITE_FAILED`: an attempted optional-cache update failed; regression detection may be degraded.

Cache-update failure does not invalidate authenticated or published objects, block credential use, or block authorship. A client may use an authenticated accepted object immediately without writing a cache record first. A hypothetical optional-cache failure cannot revoke publication acknowledgement even in a baseline conformance trial; implementations without caches need no failure-injection or diagnostic API.

Clearing optional history only forgets regression evidence. It neither repairs nor changes synchronized causal history. The UI SHOULD explain the lost detection capability; no security-critical reset/rebaseline transition exists. Loss can make an established client behave more like a fresh installation. Binding and private-key failures remain separate authoritative-state failures under Sections 10 and 16.

### 34.1 Advisory-history capability

`advisory-history` is a conformance capability identifier, not wire state or protocol negotiation. An implementation claiming this capability retains some authenticated prior-observation evidence and MUST satisfy the conditional advisory-history cases in addition to baseline requirements.

Under the specified conditional test inputs, it MUST produce the applicable diagnostic state above for non-incorporated remembered evidence, detected loss/corruption of retained/expected memory, or failed cache updates. Equivalent diagnostic representations are permitted; exact identifiers and user-visible English strings are not protocol requirements. Implementations SHOULD surface understandable UI warnings. The general recommendation to use retained history does not make diagnostics mandatory for implementations that do not claim this capability.

A claimant MUST NOT use cache-only evidence as current synchronized objects, values, or ancestry; MUST discard/ignore corrupt cache; and MUST NOT let cache persistence failure block otherwise valid use, authorship, or publication. Diagnostics MUST NOT affect object validity, H, snapshot conflict calculation, writer parent sets, or cryptographic provenance. Cache corruption cannot authenticate protocol objects. Clearing cache only loses detection capability; returning synchronized history is processed through normal accepted-snapshot semantics. No particular cache storage format or exact-object retention is required.

---

## 35. Explicit candidate use and convergence

A candidate is an exact authenticated, supported-valid, readable LIVE TOKEN for T. It may be current or historical. Candidate use MUST pin its OBJECT_ID and complete TokenValue and disclose known uncertainty: historical selection, not uniquely current, visible conflict, incomplete local snapshot, and remembered-history regression when applicable. It is explicit and non-mutating.

Cache health is not an eligibility gate. Incomplete discovery or unscoped future evidence does not block an otherwise valid candidate. Candidate use may remain available when an opaque current head blocks ordinary use. V1 convergence/authorship over an opaque current TOKEN head remains prohibited. A later understood readable descendant can move an opaque node into history and restore ordinary operation.

---

## 36. Independent immutable publication and caching

The publication boundary for synchronized immutable objects is:

```text
construct valid canonical object
→ install/publish complete immutable bytes locally
→ publication acknowledged
```

After acknowledgement, the writer may accept the object as locally authored during this process. Optional history/cache updates are best effort and independent. Cache failure after publication leaves publication successful: do not delete the object or roll it back. An object absent from a local journal is simply an immutable synchronized object; later scans rediscover it normally. No durable graph insertion or persistence attestation precedes state use or operation success.

An unacknowledged/ambiguous publication attempt MUST NOT be reported successful. Its object may or may not be visible; later discovery determines observed state. No persistent reconciliation state, publication epoch, rescan-before-authorship fence, or poisoned session is required. Retry the same bytes or repeat the logical operation, possibly producing another immutable sibling. Both are permitted. Implementations SHOULD retry already-constructed bytes when convenient for efficiency/history cleanliness. Siblings follow normal concurrency rules.

External synchronized bytes require the full reader/validation path. Self-authored bytes originate in the canonical encoder; a conforming writer MUST produce valid canonical objects but need not decrypt/reparse/revalidate its own output at runtime. Parsing, envelope decryption, provenance recomputation, or post-publication rereading MAY be defensive hardening. Canonical byte vectors, signature-input vectors, roundtrip tests, and independent implementation/vector tests demonstrate writer correctness.

---

## 37. Future semantics and envelope families

### 37.1 Routable future TOKEN

Accepted `OPAQUE_ROUTABLE TOKEN` evidence participates in the graph for its TOKEN_ID. A current opaque TOKEN head blocks that TOKEN's ordinary semantic use/authorship; historical opaque ancestry does not. Unrelated tokens continue normal ordinary use and authorship. Explicit supported candidate use remains possible.

### 37.2 Routable future DEVICE

Opaque DEVICE heads may make presentation incomplete. They do not globally block TOKEN authorship. Missing DEVICE/key availability may leave provenance UNRESOLVED; provenance does not determine credential authority.

### 37.3 Unscoped authenticated evidence

Current `OPAQUE_UNSCOPED` means this client observed authenticated v1-family state it does not understand. Clients MUST disclose this compatibility uncertainty. It MUST NOT globally block ordinary v1 TOKEN use/authorship. Hidden remote history already creates uncertainty; one unknown object must not create permanent vault-wide denial.

Exact opaque bytes MAY be retained for future compatible reprocessing. Without retained bytes, reprocessing depends on synchronized bytes becoming available again. No mandatory exact-byte security-memory record or sticky blocking lifecycle exists.

### 37.4 Unknown sibling families

Unknown sibling namespaces are ignored by v1 semantic discovery. Their names/existence cannot authenticate future evidence or change the v1 graph. An unknown sibling envelope family is likewise not authenticated semantic evidence.

### 37.5 Rolling compatibility

A future envelope family claiming rolling compatibility must publish the authenticated v1-family compatibility projection required by Section 12. V1 observes that projection only. Cooperative compatibility does not prove propagation, completeness, or availability. Wrong-size current-family files remain invalid storage evidence, never opaque evidence.

---

## 38. Ordinary consumption safety

Ordinary current TOTP generation for T requires at least one understood current TOKEN, no routable opaque current TOKEN head, complete supported current values, and exactly one distinct complete LIVE TokenValue. A supported whole-state conflict prevents ordinary generation; a uniquely tombstoned value is not LIVE.

History-cache loss, cache-write failure, incomplete discovery, or unrelated unscoped evidence do not add eligibility gates. Appropriate diagnostics accompany usable state. Section 35 defines explicit candidate use when ordinary use is unavailable.

---

## 39. Freshness and security limitations

No local freshness check establishes absence of remote concurrent history. Last-moment directory rescans are not a security boundary. Parents attest accepted causal context, not global completeness. Even Section 27's human-decision recheck cannot exclude hidden remote history.

Totipo does not provide global freshness, rollback prevention for a fresh client, guaranteed rollback detection after local history loss, synchronized-store completeness, peer propagation acknowledgement, transactional multi-file publication, prevention of valid concurrent forks, or guaranteed availability. This is intentional.

Retained advisory history can improve detection of previously observed history disappearing, apparent regression, and suspicious restoration of an older synchronized subset. This is best-effort evidence; losing it reduces detection capability. Immutable authenticated objects and DAG concurrency preserve the meaning of authored history even when later observations reveal conflict.

---

## 40. TOTP semantics

`CREDENTIAL` contains:

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

---

## 41. Canonical TLV framing

Every TLV is:

```text
TAG:u16be || LENGTH:u16be || VALUE[LENGTH]
```

`TAG` and `LENGTH` are unsigned 16-bit big-endian integers.

No indefinite, varint, short-form, or alternate length encoding exists.

A parser MUST bounds-check the entire `4 + LENGTH` bytes before reading or allocating the value.

Unless repetition is explicitly permitted, tags in one sequence are strictly increasing and appear exactly as allowed by the object grammar.

All fixed-width protocol integers use the exact listed width and unsigned big-endian representation.

---

## 42. v1 TLV registry

### 42.1 Common tags

| Tag | Name | Encoding |
|---|---|---|
| `0x0001` | `OBJECT_VERSION` | `u8`; v1 = `0x01` |
| `0x0002` | `OBJECT_TYPE` | `u8`; `0x01=TOKEN`, `0x02=DEVICE` |
| `0x0004` | `PARENT_COUNT` | `u16be`; `0..32` |
| `0x0005` | `PARENT_ID` | exactly 32 raw object-ID bytes; repeated |
| `0x0006` | `AUTHOR_TIME` | `u64be` Unix seconds; `0` means unknown |
| `0xFF01` | `SIGNATURE` | `0..72` opaque bytes; conforming writer emits DER ECDSA-P256/SHA-256; final TLV |

Tag `0x0003` is reserved in v1.

#### OBJECT_VERSION allocation

`OBJECT_VERSION` values are allocated by the published Totipo specification process for semantic grammars within an envelope family. r12 assigns `0x01`. All other values are unassigned by r12. Conforming implementations MUST NOT independently assign an unassigned value for interoperable/shared-vault use without a published Totipo specification allocating that value. r12 defines no private-use or experimental `OBJECT_VERSION` range.

Reader-side forward-compatibility handling is deliberately independent of allocation governance: an authenticated unsupported numeric value with a valid frozen routing prefix is handled conservatively as opaque state even if the current implementation does not know that value to be officially allocated. `OPAQUE_ROUTABLE` therefore means “structurally routable but semantically unsupported here,” not “officially assigned future Totipo version.” UIs and diagnostics SHOULD describe unknown/unassigned values accordingly.


### 42.2 TOKEN tags

| Tag | Name | Encoding |
|---|---|---|
| `0x0101` | `TOKEN_ID` | exactly 32 raw bytes |
| `0x0102` | `AUTHOR_DEVICE_ID` | exactly 32 raw bytes |
| `0x0103` | `STATUS` | `u8`; `0x01=LIVE`, `0x02=TOMBSTONE` |
| `0x0104` | `ISSUER` | UTF-8, `0..256` bytes |
| `0x0105` | `ACCOUNT` | UTF-8, `0..256` bytes |
| `0x0106` | `CREDENTIAL` | nested canonical TLV sequence |

### 42.3 DEVICE tags

| Tag | Name | Encoding |
|---|---|---|
| `0x0200` | `DEVICE_ID` | exactly 32 raw bytes; frozen DEVICE routing identity |
| `0x0201` | `PUBLIC_KEY_X963` | exactly 65 raw bytes |
| `0x0202` | `DISPLAY_NAME` | UTF-8, `0..256` bytes |

### 42.4 Nested CREDENTIAL tags

| Tag | Name | Encoding |
|---|---|---|
| `0x0301` | `ALGORITHM` | `u8`; `0x01`, `0x02`, `0x03` |
| `0x0302` | `DIGITS` | `u8`; `0x06`, `0x07`, `0x08` |
| `0x0303` | `PERIOD` | `u32be`; `1..2^32-1` |
| `0x0304` | `SECRET_BYTES` | raw bytes, `1..128` |

Unknown or unassigned tags are invalid for `OBJECT_VERSION=1`.

The `0x00xx` range is common framing, `0x01xx` is `TOKEN`, `0x02xx` is `DEVICE`, `0x03xx` is nested `CREDENTIAL`, and `0xFFxx` is terminal provenance data.

## 43. Parent encoding

`PARENT_COUNT` is always present.

Exactly that many immediately following `PARENT_ID` TLVs occur.

Each parent ID is exactly 32 bytes.

Raw parent values MUST be strictly increasing under unsigned lexicographic comparison. This canonical ordering simultaneously rejects duplicates.

The parent list is a syntactic set of claimed immutable object identities.

It is not a consensus-validity requirement that all parents exist, validate, have the expected semantic type, or form an ancestry antichain.

---

## 44. Exact object grammars

`TOKEN` top-level sequence:

```text
0001 OBJECT_VERSION = 01
0002 OBJECT_TYPE    = 01
0004 PARENT_COUNT
0005 PARENT_ID               repeated PARENT_COUNT times
0006 AUTHOR_TIME
0101 TOKEN_ID
0102 AUTHOR_DEVICE_ID
0103 STATUS
0104 ISSUER
0105 ACCOUNT
0106 CREDENTIAL
FF01 SIGNATURE
```

Every listed TLV is required exactly once except repeated `PARENT_ID`.

`SIGNATURE` may have zero value bytes. A zero-length signature yields `PROVENANCE_REJECTED` but does not invalidate an otherwise valid TOKEN.

`DEVICE` top-level sequence:

```text
0001 OBJECT_VERSION = 01
0002 OBJECT_TYPE    = 02
0004 PARENT_COUNT
0005 PARENT_ID               repeated PARENT_COUNT times
0006 AUTHOR_TIME
0200 DEVICE_ID
0201 PUBLIC_KEY_X963
0202 DISPLAY_NAME
FF01 SIGNATURE
```

The unsigned form used for signing omits only the complete `FF01 SIGNATURE` TLV.

A parser MUST reject:

- missing required TLVs;
- forbidden type-specific TLVs;
- duplicate non-parent TLVs;
- parent count/repetition mismatch;
- duplicate or non-increasing parent IDs;
- unknown tags/enums;
- wrong intrinsic widths for `AUTHOR_TIME`, `TOKEN_ID`, `AUTHOR_DEVICE_ID`, `DEVICE_ID`, or `PUBLIC_KEY_X963`;
- malformed UTF-8;
- out-of-range token values;
- non-canonical nested credential bytes;
- `SIGNATURE` lengths greater than 72;
- trailing bytes.

P-256 point validity, DER signature validity, availability of a matching TOKEN verification key, and signature verification affect `PROVENANCE_STATUS`, not `ASSERTION_STATUS`.

## 45. Size limits, signature reservation, and 1024-byte envelope

String maxima:

```text
ISSUER       <= 256 UTF-8 bytes
ACCOUNT      <= 256 UTF-8 bytes
DISPLAY_NAME <= 256 UTF-8 bytes
```

Credential secret:

```text
1..128 bytes
```

Syntactic parent count:

```text
0..32
```

The total canonical semantic plaintext MUST fit the 1006-byte envelope capacity.

Each 32-byte parent ID costs 36 semantic bytes.

Required common `AUTHOR_TIME` costs 12 semantic bytes:

```text
4-byte TLV header + 8-byte value
```

### 45.1 Deterministic signature-capacity reservation

P-256 ECDSA signatures are encoded as canonical DER and may vary in actual byte length.

For **writer capacity planning**, every semantic object MUST reserve:

```text
SIGNATURE_RESERVED_BYTES = 72
```

regardless of the actual generated signature length.

A conforming writer MUST NOT:

- include an additional parent merely because a particular generated DER signature is shorter than 72 bytes;
- retry ECDSA signing to obtain a shorter encoding so an otherwise over-capacity object will fit;
- make fold grouping depend on randomized signature length.

After the object shape/parent set has been chosen using the 72-byte reservation, the actual canonical DER signature bytes are serialized at their real length.

Readers continue to accept every valid canonical signature length permitted by the grammar.

### 45.2 TOKEN capacity

With 32-byte `AUTHOR_DEVICE_ID`, required `AUTHOR_TIME`, and 72-byte reserved signature:

```text
TOKEN_BYTES_RESERVED =
    215
    + ISSUER_BYTES
    + ACCOUNT_BYTES
    + SECRET_BYTES
    + 36 * PARENT_COUNT
```

Therefore:

```text
maximum fields, 0 parents = 855 bytes
maximum fields, 4 parents = 999 bytes
maximum fields, 5 parents = 1035 bytes  // capacity-plan does not fit

typical 20-byte issuer,
30-byte account,
20-byte secret,
20 parents                 = 1005 bytes
```

Every maximum-size TOKEN can plan at least four parents.

### 45.3 DEVICE capacity

A DEVICE with 65-byte public key, required `AUTHOR_TIME`, and 72-byte reserved signature has:

```text
DEVICE_BYTES_RESERVED =
    213
    + DISPLAY_NAME_BYTES
    + 36 * PARENT_COUNT
```

so a maximum 256-byte display name plans up to 14 parents:

```text
469 + 14*36 = 973 bytes
```

while 15 parents requires:

```text
469 + 15*36 = 1009 bytes
```

and MUST be folded even if the eventual DER signature would happen to be short enough to make the serialized object fit.

### 45.4 Fold progress

Usable parent fan-in is state-size-dependent but always calculated with the 72-byte signature reservation.

Writers MUST NOT truncate semantic state, omit required frontier identities, shrink user data, or alter semantics merely to force one object to fit.

For maximum-size TOKEN state:

- first fold can include four original heads;
- each later fold can include the previous staged head plus up to three additional original heads.

For maximum-size DEVICE presentation state:

- first fold can include fourteen original heads;
- each later fold can include the previous staged head plus up to thirteen additional original heads.

Therefore bounded TOKEN and DEVICE convergence makes forward progress over every finite frontier.

---

## 46. Strings and safe presentation

Human-facing strings are UTF-8. The protocol performs no Unicode normalization. Limits are measured in encoded UTF-8 bytes.

Empty `ISSUER`, `ACCOUNT`, and `DISPLAY_NAME` strings are format-valid.

Human-facing strings are untrusted presentation data.

UIs and diagnostic tools MUST render them safely and MUST NOT allow control characters, bidirectional rendering behavior, terminal escapes, markup interpretation, or similar effects to obscure cryptographic identity or security warnings.

Diagnostics MUST redact `SECRET_BYTES` by default.

---

## 47. Normal TOKEN writes and bounded folds

A one-object write parents exactly `CURRENT_TOKEN_HEADS(T, S)` from its accepted planning snapshot S and carries one complete resulting value. Visible supported conflict requires Section 27 confirmation. Set AUTHOR_TIME under Section 20.1.

### 47.1 One-object write

Accept snapshot S, select exact H, obtain required confirmation, construct/sign the canonical TOKEN, perform the TOKEN-specific confirmation recheck if applicable, and publish complete immutable bytes. Report publication success on acknowledgement. Runtime self-validation and cache insertion are not prerequisites. Ordinary writes have no final frontier recheck.

### 47.2 Active multi-object fold

If H does not fit under Section 45's unchanged 72-byte signature reservation, use a linear fold of ordinary TOKENs carrying the same chosen/confirmed complete value and the same AUTHOR_TIME captured before signing the first stage. Remember the original H, chosen value, operation intent, and exact locally generated intermediates in process.

For an illustrative TOKEN state whose reserved-size calculation leaves capacity for four parents:

```text
H1 H2 H3 H4  -> M1(S)
M1 H5 H6 H7  -> M2(S)
M2 H8 H9 H10 -> FINAL(S)
```

Each stage parents the previous staged head, if any, plus as many unincorporated original heads as fit. Every original head MUST be an ancestor of FINAL through the constructed fold. Required parents MUST NOT be dropped merely to fit. Each stage is a valid complete immutable assertion; publication acknowledgement suffices. No durable journal is required. Locally generated stages implementing the same confirmed decision do not stale that decision.

### 47.3 No transaction across stages

Other clients may use M1 before FINAL. Uncovered original heads remain current where available. A fold is not an atomic distributed transaction and adds no wire batch markers. New remote concurrency does not invalidate already-published stages. Finalization incorporates the intentionally selected frontier under these coverage rules, not a claimed globally complete frontier.

### 47.4 New observations and interruption

For a confirmed conflict resolution, newly learned TOKEN-relevant semantic information requires Section 27 reconfirmation before further publication; unrelated events do not. Ordinary folds may continue against their chosen snapshot. On interruption, published stages remain ordinary history. Restart discards in-process confirmation/staging and plans from a new accepted snapshot, confirming visible conflict as needed. Missing intermediates may leave unresolved ancestry and regression warnings; optional cache topology cannot silently repair the current graph.

---

## 48. Whole-state convergence write

For visible supported conflict, derive H from an accepted snapshot, show exact complete alternatives and the intended resulting value, and obtain Section 27 confirmation. Publish a complete TOKEN parenting all H, or use Section 47's bounded fold. Recompute the TOKEN-specific confirmation context immediately before publication and reconfirm if changed.

The user can choose an existing complete candidate, start from a historical candidate, or compose one complete desired value. The resulting TOKEN records that value and parent identities, not the user's reasoning. Missing remembered history generates advisory warnings, not mandatory unavailable-state confirmation. Publication and optional cache persistence are independent.

---

## 49. DEVICE writes and wide frontiers

A rename uses an accepted DEVICE snapshot and requires no opaque current DEVICE head for the target DEVICE_ID. Its rename frontier is the complete current supported DEVICE frontier, including provenance VERIFIED, UNRESOLVED, and REJECTED heads. Parenting a presentation-inert assertion incorporates causality without endorsing its name or provenance.

A correctly signed rename parents every such head and carries the chosen name. If capacity requires folding, use the same selected name and AUTHOR_TIME in every stage; parent the prior stage and additional original heads until all original heads are ancestors of FINAL. No transaction or durable graph record is required. Relevant new DEVICE presentation can prompt recomputation; earlier published stages remain valid. DEVICE presentation uncertainty does not change TOKEN authority.

---

## 50. Filesystem obligations and durability

### 50.1 Reads and namespace

Under Section 3's trusted local execution boundary, readers MUST use exact canonical names, direct ordinary files, bounded reads/allocations, and normal cryptographic validation. Only direct regular-file children of `objects-v1/` with 64 lowercase hexadecimal names are object candidates. Observed symlinks, directories, FIFOs, sockets, and devices are not candidates; do not deliberately follow observed symlinks or traverse arbitrary paths. Ignore temporary/conflict names and sibling namespaces. Metadata is not authentication. Wrong-size files are never authenticated opaque evidence.

Churn/read/resource failures produce unavailable/incomplete observations. Successfully accepted objects remain usable. No same-UID TOCTOU, stable inode, or path-identity proof is required.

### 50.2 Immutable synchronized writes

Writers MUST install complete exact 1024-byte objects at exact canonical OBJECT_ID filenames with atomic/complete visibility at the local filesystem API boundary. Temporary-file handling MUST prevent accidental collisions/clobbering. Use immutable no-replace installation or equivalent exclusion; never overwrite different existing bytes.

`ALREADY_PRESENT_EXACT`: an ordinary accepted file at the canonical target containing exactly the intended 1024 bytes suffices for local publication acknowledgement. Exact-byte equality is enough; no fsync of that existing provider file, directory fsync merely for existing presence, reread after fsync, or inode identity proof is required. A mismatched existing target fails publication and MUST NOT be replaced.

New synchronized objects SHOULD use complete temp → file flush/force → no-replace install → directory flush/force for reliability. Lack of physical crash durability is not a protocol-authenticity failure. An acknowledged object may later disappear; this is availability degradation, not retroactive invalidation. Ambiguity follows Section 36.

### 50.3 Authoritative local durability

VAULT, local VAULT_BINDING, and private-key custody MUST be crash-safe. The straightforward pattern is complete temporary file → file durability barrier → atomic install/replacement → containing-directory durability barrier, with equivalent platform mechanisms acceptable. No mandatory reread or stable inode proof is needed for crash durability. VAULT MUST NOT be partially rewritten in place. Key storage must additionally preserve privacy and prevent accidental replacement.

### 50.4 Advisory cache

History-cache durability is best effort. A flushed atomic replacement snapshot may improve reliability, but failure/corruption means warn, discard/rebuild, and continue. It cannot turn successful object publication into failed protocol authorship.

---

## 51. Privacy properties

Before unlock, a storage observer can see bootstrap size/replacement activity, the existence and names of top-level storage-family namespaces, number of object files per visible family namespace, object creation timing, total vault size, and equality of identical filenames/ciphertexts within a family.

For v1-family objects, semantic token values, logical token/device routing IDs, device keys, parent references, `AUTHOR_TIME`, opaque future bodies, unpadded semantic length, and object types are encrypted.

Every valid object in `objects-v1/` is exactly 1024 bytes.

Fixed size prevents exact v1-family semantic length/type leakage through object file length but does not provide traffic-analysis resistance.

A future family may define different privacy/size properties in its own namespace.

Full-state TOKEN objects intentionally repeat token secrets and metadata. This increases encrypted redundancy compared with delta-based designs and is accepted in exchange for history-independent value availability.

The 1024-byte family envelope balances padding/privacy, synchronization/storage overhead, and bounded parent fan-in.

---

## 52. Deterministic object-encryption rationale

v1 intentionally derives:

```text
OBJECT_ID = HMAC(K_id, canonical_plaintext)
K_object  = HKDF(..., full OBJECT_ID)
nonce     = first 12 bytes of OBJECT_ID
```

A distinct semantic plaintext is expected to derive a distinct full object ID and therefore a distinct encryption key.

A 96-bit nonce-prefix collision between different object IDs does not by itself reuse a nonce under the same key because the keys differ.

Repeating identical canonical semantic plaintext repeats the same ID, key, nonce, AAD, padded plaintext, and ciphertext, consistent with content addressing.

Canonical deterministic padding is mandatory because alternate padded plaintexts under one derived key/nonce pair are forbidden.

Post-decryption keyed-ID recomputation is mandatory.

---

## 53. Security meaning of authentication and writer policy

Vault authentication establishes complete object integrity under K_root; provenance attributes signatures without introducing membership authorization. Signed parents express exact incorporated history in the accepted planning snapshot. They do not prove completeness, propagation, or freshness.

Reader validity and writer conformance are distinct. A cryptographically/canonically valid TOKEN remains reader-valid even if its writer violated confirmation policy, recommended regression-warning handling, or retry guidance: the wire cannot prove client-side intent. Known visible whole-state conflicts still require explicit confirmation from conforming writers.

The simplification is not a wire downgrade. Cryptographic and encoding protections are unchanged; r15 removes local assumptions that cannot deliver global guarantees over unreliable synchronization.

---

## 54. Core invariants

- K_root is stable; the authoritative durable local VAULT_BINDING pins identity.
- Private-key custody is authoritative local state; remembered history is advisory.
- Canonical crypto/wire, keyed OBJECT_ID, immutable objects, and exact authenticated parent claims remain unchanged.
- Every valid object in objects-v1/ is exactly 1024 bytes. Wrong-size files never become opaque evidence.
- Complete TokenValue semantics prohibit silent field merging; LIVE/TOMBSTONE does not provide secure deletion.
- Current graphs derive from ACCEPTED_SNAPSHOT; cached history cannot silently become current evidence.
- Ordinary parents equal exact H from the accepted planning snapshot; later history creates normal concurrency, not retroactive invalidity.
- Known visible supported whole-state conflict requires TOKEN-specific semantic confirmation.
- Routable opaque current TOKEN heads block that TOKEN; unscoped authenticated evidence warns without a global authorship block.
- Invalid current-family bytes and unknown sibling families are not authenticated future evidence.
- No local scan proves global completeness or freshness; publication does not prove peer propagation.
- Cache persistence is not a state-use or publication-success prerequisite.
- Same-ID authenticated contradictions and resolved cycles fail evaluated graph integrity.
- ECDSA uses cryptographically secure signing nonces; K_signature_context binds provenance to one vault root.

---

## 55. Required conformance evidence for v1

The moving-pre-RC requirement profile is the baseline protocol set. Every case has explicit manifest applicability: baseline or conditional `advisory-history`. Baseline conformance requires no advisory cache. The conditional suite is required only when that capability is claimed; both kinds remain hash-pinned normative evidence when applicable. The reference implementation declares its supported capability and executes both suites. Accepted snapshots, graph/head/conflict interpretation, canonical VAULT authentication, VAULT_BINDING, private-key custody, and external cryptographic validation remain baseline obligations.

Before v1 byte-level release-candidate freeze, executable evidence MUST cover at least:

### Bootstrap and root binding

- exact 87-byte `TOTIPO-VLT` bootstrap vectors;
- wrong magic/version/length rejected before Argon2id;
- Argon2id known-answer vectors;
- wrong-password and mutated-header/ciphertext/tag rejection;
- same-root rewrap recovery;
- optional remembered exact-VAULT fingerprint warning for same-root representation change;
- no-replace first creation;
- absent binding first-open establishment, corrupt binding recovery, and crash after VAULT before binding;
- differing-root binding rejection.

### Storage-family namespace, canonical encoding, and object crypto

Baseline v1 conformance does not require executable proof of immunity to a malicious same-privilege local process deliberately racing namespace or inode changes between filesystem syscalls. Such tests are implementation hardening evidence, not interoperable protocol conformance evidence.

- statically observed symlink/directory/FIFO/socket/device entries are not v1 object candidates;
- candidate disappearance/change/unavailability during processing produces unavailable/incomplete behavior rather than invented semantic knowledge;
- bounded reads do not allocate based on hostile metadata;
- immutable publication does not overwrite an existing object;
- interrupted/ambiguous publication is not reported as success;

- exact v1-family namespace is `objects-v1/`;
- v1 discovery ignores unknown sibling namespaces such as `objects-v2/`;
- unknown sibling namespace existence never creates opaque semantic evidence;
- 64-hex candidate under `objects-v1/` with wrong file length is invalid storage evidence, not `OPAQUE_ROUTABLE`/`OPAQUE_UNSCOPED`;
- authenticated future semantic version inside a valid 1024-byte v1-family envelope reaches opaque classification;
- synthetic future-family richer state plus v1-family compatibility assertion is observed by old v1 only through the compatibility assertion;

- exact TLV positive/negative vectors;
- `OBJECT_VERSION=1` / `TOKEN` / `DEVICE` dispatch;
- future TOKEN routing prefix => OPAQUE_ROUTABLE with body uninterpreted;
- future DEVICE routing prefix with explicit DEVICE_ID => OPAQUE_ROUTABLE;
- unknown type/incompatible future routing prefix => OPAQUE_UNSCOPED;
- required full token grammar;
- parser-level parent-count bound and envelope-limited effective fan-in;
- maximum-field TOKEN with 4 parents accepted and 5 parents rejected for capacity planning;
- writer capacity planning always reserves 72 signature bytes;
- shorter DER cannot increase selected parent count; retry-to-fit prohibited;
- maximum-display DEVICE with 14 parents fits one planned object and 15 parents requires fold;
- small-state TOKEN parent fan-in boundary vectors;
- duplicate/non-increasing parents rejected;
- parent semantic invalidity tested separately from object grammar;
- exact 1024-byte envelope vectors;
- semantic length boundaries;
- non-zero padding rejection;
- object-ID recomputation;
- HKDF/HMAC/AES-GCM known-answer composition.

### P-256 provenance

- native-platform ECDSA P-256/SHA-256 positive vectors;
- exact serialized DEVICE_ID[32] and v1 equality to the public-key derivation;
- exact DEVICE 65-byte ANSI X9.63 uncompressed public-key encoding;
- DEVICE_ID SHA-256 domain-separation vectors;
- TOKEN AUTHOR_DEVICE_ID key-discovery/verification vectors;
- missing DEVICE key material => TOKEN provenance unresolved, TOKEN state retained;
- late matching DEVICE/key arrival causes affected known TOKEN provenance to be recomputed from UNRESOLVED to VERIFIED or REJECTED without changing TOKEN value authority or causality;
- malformed/non-curve DEVICE public key => DEVICE provenance rejected; TOKEN using its derived ID cannot verify;
- valid DER ECDSA signatures of multiple legal lengths and zero-length rejected-provenance fixture;
- malformed DER => provenance rejected, TOKEN state retained;
- mathematically invalid signature => provenance rejected, TOKEN state retained;
- randomized signatures for identical message/key are accepted;
- signing implementation uses cryptographically secure ECDSA nonce generation; no ad-hoc Totipo nonce generator;
- same device key + same unsigned object under different `K_signature_context` values verifies only in the matching vault context;
- a fresh local device identity MUST withhold first TOKEN success until matching valid DEVICE and TOKEN local publication acknowledgements;
- exact v1 `totipo/v1/token` and `totipo/v1/device` signature-input vectors including AUTHOR_TIME;
- AUTHOR_TIME=0 unknown case and positive u64 case;
- AUTHOR_TIME=0x7fffffffffffffff and 0xffffffffffffffff remain structurally valid and non-causal;
- platform date-conversion overflow cannot invalidate or crash semantic processing;
- implausible/future AUTHOR_TIME accepted without semantic ordering effect;
- Java, Android, and Apple cross-verification vectors.

### TOKEN semantics

- creation;
- sequential edit;
- equal-valued concurrent heads => unambiguous;
- differing concurrent heads => whole-state conflict;
- disjoint concurrent edits => conflict, not automatic composition;
- complete-state user convergence over multiple heads;
- convergence may choose an existing state or a newly confirmed composite state;
- hidden incomparable equal state => unambiguous;
- hidden incomparable differing state => conflict reappears;
- delete vs credential rotation => whole-state conflict;
- matching deletes => unambiguous;
- parentless duplicate root with same/different value;
- signer identity never creates token ordering;
- TOKEN with verified/rejected/unresolved provenance has identical value authority;
- equal TOKEN_VALUE with differing AUTHOR_TIME remains semantically equal;
- differing AUTHOR_TIME never orders concurrent TOKENs;
- rejected provenance cannot be rendered as authenticated device attribution;
- verified child TOKEN may reaffirm a rejected-provenance current TOKEN without deleting history;
- wide-frontier convergence batch fully covers all original heads;
- batch intermediate publication does not stale its own confirmation;
- new TOKEN-relevant semantic information during a confirmed batch requires reconfirmation;
- every acknowledged fold TOKEN is accepted locally without mandatory caching;
- finalized multi-object fold covers all original heads through its constructed ancestry;
- missing intermediates may leave ancestry unresolved in a later snapshot;
- interrupted folds retain valid published stages; restart plans from current accepted evidence.

### Parent-edge semantics

- missing parent => valid complete child + unresolved edge;
- parent arrives => causality becomes resolved without changing child value;
- wrong-token parent => child valid + rejected edge;
- wrong-type parent => child valid + rejected edge;
- intrinsically invalid bytes at a referenced pathname => child valid + parent edge remains unresolved;
- redundant parents discovered later => child remains valid;
- unresolved edges do not suppress other heads;
- rejected edges do not suppress other heads;
- traversal cycle defense;
- arrival-order invariance.

### Accepted snapshots and advisory history

Snapshot, graph, and operation rules below are baseline requirements. History-derived diagnostics are conditional on the Section 34.1 advisory-history capability; a client without it need not synthesize loss/regression/cache warnings.

- exact parent choice from a supplied accepted snapshot;
- late concurrent arrival before/after publication preserves authored validity;
- unrelated TOKEN/DEVICE changes do not stale ordinary writes or conflict confirmation;
- visible conflict remains confirmed; relevant semantic-context changes require reconfirmation;
- conditional advisory-history: detected loss/corruption of previously retained/expected memory or failed cache update => diagnostic, current graph independent and ordinary operations available;
- remembered absent history => regression warning, not a current head or unavailable-state confirmation;
- incomplete processing preserves accepted usable state and never validates failed candidates;
- current unscoped evidence => compatibility warning without global blocking;
- routable opaque current TOKEN => scoped blocking;
- same-ID contradiction and resolved cycles => integrity failure;
- ambiguous publication => non-success, later discovery, permitted retry siblings;
- exact-existing publication requires exact bytes, no persistence barrier in semantic validity;
- optional exact opaque retention and later reprocessing are implementation choices.

### DEVICE semantics

- supported provenance-REJECTED/UNRESOLVED current DEVICE heads are presentation-inert;
- rename/convergence parents every current supported DEVICE head regardless of provenance status;
- rejected-provenance current DEVICE head becomes historical after a verified rename that causally incorporates it;

- root;
- rename;
- equal-valued concurrent names => unambiguous;
- differing names => presentation conflict;
- missing parent => verified current name may remain usable while ancestry is incomplete;
- wrong-device parent => rejected edge, child presentation assertion remains valid;
- token objects cannot become device causal parents;
- current DEVICE value unavailable => fingerprint/DEVICE_ID warning, not silent older-name fallback;
- missing DEVICE/key material may degrade remote provenance without invalidating TOKENs;
- current friendly name is not implied to be historical friendly-name metadata for older TOKENs.

### Future semantic-version and envelope-family interoperability

- semantic `OBJECT_VERSION` evolves inside the fixed `objects-v1/` envelope family;
- future envelope family is separate from semantic version and may use another sibling namespace;
- unknown sibling family directory/file names are not authenticated semantic evidence;
- future family claiming rolling compatibility publishes v1-family compatibility assertions into `objects-v1/`;

- routable future TOKEN becomes opaque graph node;
- opaque TOKEN participates in ancestry/current-head selection;
- opaque TOKEN body is not parsed as v1;
- affected token ordinary use is incomplete while opaque head is current;
- unrelated tokens remain usable/writable;
- candidate use remains available for affected token;
- v1 authorship over opaque current TOKEN is blocked;
- later supported descendant can restore old-client ordinary semantics;
- routable future DEVICE affects only presentation/provenance scope;
- opaque-unscoped evidence warns without blocking ordinary operations;
- disappearance updates snapshot evidence; optional history supports warnings;
- semantic version number never orders state.

### TOTP

- RFC 6238 SHA-1/SHA-256/SHA-512 vectors;
- 6/7/8 digits;
- period/time boundaries;
- secret length limits.

At least two independent implementations MUST consume the frozen v1 vectors before v1-rc1 is declared frozen.

---

---

---

## 56. Open work after r15

Before v1-rc1, independently consume frozen vectors in at least two implementations, cross-verify native P-256/password handling, test production bounded storage reads and complete immutable no-overwrite publication, and verify strong VAULT/binding/key durability. Review snapshot parent choice, TOKEN-specific confirmation, bounded fold interruption, optional regression diagnostics, and ordinary concurrency. Go race tests remain implementation race detection, not a global sync-freshness proof.

Downstream implementation impact (non-normative): replace durable graph journals as a security boundary with optional caches; remove continuity/persistence/global discovery gates, ordinary frontier rechecks, publication reconciliation fences, runtime self-reader requirements, and synchronized existing-file fsync requirements. Narrow confirmation freshness, simplify first DEVICE acknowledgement and binding establishment, and retain strong VAULT/binding/private-key durability. This revision does not edit downstream implementations.

---

## 57. v0 concepts intentionally absent from v1

The following v0 concepts are not part of Totipo v1:

```text
TOKEN_UPDATE
DEVICE_UPDATE
partial token field assertions
BASE_STATE value inheritance
FIELD_REVISION
FIELD_PARENTS
typed field ancestry
per-field JOIN
per-field conflicts
equal-valued revision conflict
credential witness history
lifecycle witness oracle
lifecycle-resolution candidate
status-only lifecycle resolution
pending TOKEN because a parent is unavailable
pending-history abandonment
recovery TOKEN/object/bit
history generation ID
graph-only merge objects
```

The security goals previously served by those mechanisms are addressed by complete vault-authenticated token state, whole-state conflict semantics, complete-frontier user confirmation, accepted authenticated topology, explicit candidate-use handling, and no-field-merge behavior.

---

## 58. Revision history

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
