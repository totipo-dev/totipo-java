# Totipo Vault Format v1

**Status:** design draft, revision 10  
**Protocol version:** 1  
**Revision:** r10  
**Scope:** encrypted append-only TOTP vault format, complete-state token assertions, token-local causal history, device presentation history, durable local rollback evidence, bootstrap semantics, cryptographic construction, canonical encoding, and writer/application safety.

**Historical note:** Earlier Totipo design work used a v0 draft. It was never released as an implemented/deployed protocol and is not a supported predecessor of v1. v1 defines no migration protocol from v0; historical v0 draft artifacts are outside the v1 protocol.

**Revision 10 summary:** v1/r10 makes the envelope-family boundary explicit in storage. The Totipo v1 envelope family owns the exact top-level namespace `objects-v1/`; every candidate in that namespace uses the fixed 1024-byte v1-family envelope and frozen routing contract. `OBJECT_VERSION` continues to version semantics inside that family. A genuinely new envelope/storage family uses a different sibling namespace (for example `objects-v2/`) and is not parsed or trusted merely because that directory exists. A future family that claims rolling-upgrade interoperability with v1 must publish authenticated v1-family compatibility assertions into `objects-v1/`, so old clients can degrade through the existing `OPAQUE_ROUTABLE` machinery rather than going blind.

---

## 1. Goals

Totipo v1 is an encrypted, append-only, multi-device TOTP vault format intended for synchronization over an untrusted or partially trusted file-synchronization medium such as Syncthing, Dropbox, or Google Drive.

The principal goals are:

- small and auditable format and implementation surface;
- confidentiality against the synchronization medium;
- immutable authenticated content storage;
- deterministic synchronization-derived interpretation of the same observed object set;
- deterministic effective state given the same synchronized observations and the same durable known-graph/security state;
- complete usable token state in every vault-authenticated TOKEN;
- explicit preservation of genuine concurrent disagreement;
- no silent field-wise synthesis of a state that no user confirmed;
- graceful availability when historical ancestry is missing;
- device provenance without a device-authorization system;
- durable local detection of already-known history disappearing;
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

A client MAY maintain disposable indexes and materialized token views. The durable known graph required by Section 24 is security memory rather than a disposable cache and is intentionally not synchronized protocol state.

## 3. Threat model

The synchronization medium MUST NOT be trusted for confidentiality, integrity, freshness, ordering, completeness, or availability.

An attacker controlling the synchronization medium may read, copy, add, replace, replay, reorder, withhold, or delete files.

Without `K_root`, such an attacker MUST NOT be able to:

- decrypt semantic object contents;
- compute valid object identifiers for guessed plaintext;
- construct a new valid v1 semantic object;
- substitute a different v1 vault root without detection by an established client.

Possession of `K_root` grants vault read capability and permits creation of a fresh vault-specific P-256 device provenance identity. v1 defines no additional protocol membership or authorization check.

Device provenance signatures provide attribution, not authorization.

Possession of `K_root` alone MUST NOT permit forging **verified provenance** attributed to an already-existing device public key without that device's private signing key. A holder of `K_root` can nevertheless author vault-valid TOKEN state because v1 authorization is rooted in vault-key possession rather than device membership.

A compromised unlocked client is assumed capable of reading token secrets, reading `K_root`, generating a fresh device signing identity, and creating valid new v1 `TOKEN` and `DEVICE` objects under that fresh identity.

This threat model is important to the ancestry rules: a signer capable of creating an otherwise valid complete `TOKEN` already has semantic write capability. Invalidating that complete state solely because a parent edge is unavailable or semantically unusable would create an availability attack without removing write capability from an authorized vault holder.

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

Writers SHOULD publish immutable v1-family objects using a completed temporary file followed by atomic no-replace or equivalent immutable installation where available.

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

Before initial bootstrap publication, the client MUST durably persist the pending local `VAULT_BINDING` from Section 10.

Initial bootstrap installation MUST use no-replace semantics or an equivalent local exclusion guarantee.

Creation MUST NOT be reported successful until the installed bootstrap has been reopened, authenticated, shown to recover the intended `K_root`, matched against the pending local binding, and the local establishment state has become durably `ESTABLISHED`.

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

A conforming writer MUST:

1. construct the complete candidate bootstrap in a separate temporary file in the same filesystem/storage context in which atomic installation can be attempted;
2. write the complete candidate bytes;
3. durably flush the temporary file to the extent supported by the platform;
4. reopen and validate the completed temporary bootstrap locally:
   - for initial creation, require that the configured password unwraps exactly the newly generated `K_root` and derives the `VAULT_BINDING` about to be pinned;
   - for replacement, require that the new password unwraps exactly the already-established unchanged `K_root` and derives the already pinned `VAULT_BINDING`;
5. for initial creation, install with no-replace semantics or equivalent local exclusion;
6. for replacement, atomically replace the canonical `vault` pathname where the platform provides atomic replace/rename;
7. durably flush containing-directory metadata when the platform provides such a facility;
8. reopen/authenticate the installed canonical bootstrap;
9. report creation or password-change success only after all required publication and local-security-state persistence steps complete.

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

## 10. Durable local vault binding, first establishment, and bootstrap continuity

Derive:

```text
VAULT_BINDING =
    HMAC-SHA-256(
        K_root,
        ASCII("totipo/v1/local-vault-binding")
    )
```

`VAULT_BINDING` is local-only durable security state.

A configured vault has local establishment state:

```text
UNESTABLISHED
PENDING(VAULT_BINDING)
ESTABLISHED(VAULT_BINDING)
```

A client MUST NOT report ordinary creation/open success, reuse a configured device provenance key, expose ordinary current credential state, or author semantic objects until the configured vault is durably `ESTABLISHED`.

### 10.1 Initial creation

Before installing the canonical initial `vault`, the client MUST durably persist:

```text
PENDING(VAULT_BINDING)
```

for the newly generated `K_root`.

Initial publication then follows Section 9.1.

After installation, the client MUST reopen/authenticate the canonical `vault`, require that it unwraps to a root deriving exactly the pending binding, and only then durably transition to:

```text
ESTABLISHED(VAULT_BINDING)
```

### 10.2 First open of an existing vault

A newly configured client opening an already-existing vault:

1. validates/authenticates the canonical bootstrap;
2. unwraps `K_root`;
3. derives `VAULT_BINDING`;
4. durably establishes that binding for the configured vault before exposing ordinary state or creating/reusing a device provenance key;
5. then performs semantic-object scanning and durable known-graph insertion.

An implementation MAY use a transient `PENDING` step or one atomic durable establishment operation, provided a crash cannot result in ordinary use under an unpinned root.

### 10.3 Restart with pending establishment

If `PENDING(VAULT_BINDING)` exists and canonical `vault` is present:

- authenticate/unwrap the canonical bootstrap;
- require that it derives exactly the pending binding;
- only then transition to `ESTABLISHED`;
- a differing root stops automatic establishment and requires explicit abort/reconfiguration.

If `PENDING(VAULT_BINDING)` exists and canonical `vault` is absent:

- setup remains incomplete;
- the client MUST NOT silently establish a different root;
- it MAY resume the original creation only if retained candidate material can reproduce a bootstrap/root deriving exactly the pending binding;
- otherwise explicit user-directed abort/reconfiguration is required before another vault can be established.

### 10.4 Subsequent opens

On every later open, the unwrapped candidate root MUST derive exactly the established `VAULT_BINDING`.

A differing binding means a different vault. The client MUST NOT silently switch roots or reuse the existing device provenance identity.

A locally stored device private key MUST be bound to the same established `VAULT_BINDING`.

### 10.5 Same-root VAULT representation rollback

A password change rewraps the same `K_root`. Historical bootstrap copies can therefore remain usable with their historical passwords.

An established client MAY retain:

```text
LAST_ACCEPTED_VAULT_FINGERPRINT =
    SHA-256(exact 87-byte VAULT representation)
```

as local audit/usability evidence.

After a successful unwrap that derives the established `VAULT_BINDING`, if the exact bootstrap representation differs from the remembered representation and the client did not itself just complete that rewrap, the client MAY warn that the same root is being presented through a different bootstrap representation.

Such a difference can represent a legitimate rewrap, a concurrent rewrap, or replay/rollback to an older same-root bootstrap.

Because `K_root` is unchanged, the warning does not alter TOKEN state authority.

A successfully accepted local password change SHOULD advance the remembered fingerprint only after the new canonical `vault` is durable and has been reopened/authenticated.

Password rewrap MUST NOT be described as secure revocation of older bootstrap copies/passwords.

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

A future-family writer claiming rolling compatibility MUST ensure the required v1-family compatibility assertion becomes durable no later than it reports the corresponding future-family semantic action successful.

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

Implementations SHOULD use platform crypto implementations rather than bundle independent elliptic-curve arithmetic merely for Totipo.

ECDSA signatures need not be deterministic. Randomized signatures are valid and expected.

A conforming writer emits the signature as canonical DER ECDSA `(r,s)` bytes. For P-256 the field is bounded to `0..72` bytes; a zero-length signature is an explicit no-valid-signature representation and yields rejected provenance.

High-S and low-S mathematically valid ECDSA signatures are both acceptable. v1 does not use signature normalization as semantic identity.

Provenance-verifier differences MUST NOT change `TOKEN` value authority.

### 16.1 Public-key availability for TOKEN provenance

A verifier may obtain the P-256 public key for `AUTHOR_DEVICE_ID` from:

- an `ASSERTION_VALID DEVICE` whose derived `DEVICE_ID` matches;
- the durable `KNOWN_DEVICE_NODE.PUBLIC_KEY_X963` record from Section 24;
- locally bound key material for the same established vault.

An established client MUST retain the exact 65-byte `PUBLIC_KEY_X963` in its durable DEVICE graph record after learning an assertion-valid DEVICE.

The `DEVICE` object's own friendly-name provenance signature need not verify in order for its exact structurally valid public-key bytes to be retained as candidate verification material for a TOKEN. The TOKEN signature independently proves possession of the corresponding private key.

If no matching public-key bytes are available in synchronized data, durable graph state, or locally bound key material, TOKEN provenance is `UNRESOLVED`.

If matching public-key bytes are available but do not decode as P-256, or the TOKEN signature fails, TOKEN provenance is `REJECTED`.

If the signature verifies, TOKEN provenance is `VERIFIED`.

A SHA-256 collision causing two distinct canonical public keys to share one `DEVICE_ID` is outside the ordinary threat model. If an implementation ever observes distinct public-key byte strings for one `DEVICE_ID`, it MUST treat provenance for that identity as rejected/anomalous rather than choose one.

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

A conforming writer creating a new logical token uses a fresh random `TOKEN_ID`, no parents, its local `DEVICE_ID` as `AUTHOR_DEVICE_ID`, one Section 20.1 `AUTHOR_TIME`, and a locally verified provenance signature.

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

Because ECDSA signing is randomized, two otherwise identical actions may produce distinct signatures and object IDs. This is acceptable.

A conforming writer MUST locally verify its newly generated signature before publishing.

Readers classify provenance independently from state assertion validity under Section 21.

A `TOKEN` signature is verified against public-key material whose derived `DEVICE_ID` equals `AUTHOR_DEVICE_ID`.

A `DEVICE` signature is self-verified against the `PUBLIC_KEY_X963` contained in that `DEVICE`.

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

## 22. Durable parent claims, edge status, and graph-integrity failures

Supported-valid objects and opaque-routable future objects both contain vault-authenticated frozen parent claims.

Once such a TOKEN/DEVICE routing record is durably persisted, its immutable parent claims remain known even if synchronized bytes later disappear.

For TOKEN, a parent edge resolves when the exact parent is a supported-valid or opaque-routable TOKEN with the same `TOKEN_ID`.

For DEVICE, it resolves when the exact parent is a supported-valid or opaque-routable DEVICE with the same `DEVICE_ID`.

A durable authenticated record at the exact ID with wrong type/logical identity rejects the edge.

Current-path absence, unreadability, AEAD failure, keyed-ID mismatch, or invalid supported-version body leaves an otherwise unknown edge unresolved.

Resolved TOKEN and DEVICE graphs MUST be acyclic.

Within one vault, one `OBJECT_ID` identifies exactly one authenticated semantic byte string and one immutable routing record. The namespace includes supported-valid, opaque-routable, and opaque-unscoped records.

A cycle or inconsistent global-ID reuse is local graph-integrity failure and forces `LOCAL_CONTINUITY_UNKNOWN`.

---

## 23. Durable known ancestry and concurrency

For two durable TOKEN routing nodes `A` and `B` with the same `TOKEN_ID`, each supported-valid or opaque-routable:

```text
A <c B
```

iff a resolved parent path leads from `B` to `A`.

Two nodes are concurrent when neither is in the other's ancestry.

Semantic version, device identity, arrival order, filename order, `AUTHOR_TIME`, and value equality never create ordering.

The analogous DEVICE relation uses same-`DEVICE_ID` resolved edges.

Durable ancestry is independent of byte availability and whether this client understands the version-specific body.

---

## 24. Durable known graph, opaque semantics, discovery, and current token frontier

An established client durably remembers supported-valid TOKEN/DEVICE nodes, opaque-routable TOKEN/DEVICE nodes, and opaque-unscoped authenticated evidence.

Minimum TOKEN routing record:

```text
KNOWN_TOKEN_NODE {
    OBJECT_ID
    OBJECT_VERSION
    SEMANTIC_STATUS = SUPPORTED_VALID | OPAQUE_ROUTABLE
    TOKEN_ID
    PARENT_ID [...]
    AUTHOR_DEVICE_ID
    AUTHOR_TIME
}
```

Minimum DEVICE routing record:

```text
KNOWN_DEVICE_NODE {
    OBJECT_ID
    OBJECT_VERSION
    SEMANTIC_STATUS = SUPPORTED_VALID | OPAQUE_ROUTABLE
    DEVICE_ID
    PARENT_ID [...]
    AUTHOR_TIME
    PUBLIC_KEY_X963?   // required for supported v1 DEVICE
}
```

### 24.1 Durable insertion

New authenticated supported/opaque security knowledge MUST be durably persisted before authoritative operations may rely on the updated interpretation.

Failure to persist learned authenticated security information sets `KNOWLEDGE_PERSISTENCE_BLOCKED` and blocks both authoritative and candidate operations.

### 24.2 Common readiness predicates

```text
BASE_OPERATION_SAFE =
    LOCAL_CONTINUITY_UNKNOWN == false
    and KNOWLEDGE_PERSISTENCE_BLOCKED == false

AUTHORITATIVE_VAULT_READY =
    BASE_OPERATION_SAFE
    and DISCOVERY_STATE == READY
    and no OPAQUE_UNSCOPED evidence is active

CANDIDATE_USE_READY =
    BASE_OPERATION_SAFE
```

### 24.3 Discovery

`DISCOVERY_STATE` is `READY` or `PROCESSING_INCOMPLETE`.

Ordinary current use and semantic authorship require `READY`.

Candidate use may proceed during incomplete discovery when `CANDIDATE_USE_READY` and the selected exact candidate is already supported-valid/readable LIVE state.

### 24.4 Known current TOKEN heads

`KNOWN_TOKEN_NODES(T)` contains both supported-valid and opaque-routable TOKEN nodes for `TOKEN_ID=T`.

`KNOWN_CURRENT_TOKEN_HEADS(T)` are the maximal such nodes under resolved ancestry.

Opaque TOKEN nodes therefore participate fully in current-head selection.

### 24.5 Supported-value and opaque-current status

`TOKEN_VALUE_READABLE(X)` applies only to a supported-valid TOKEN whose trustworthy complete bytes are currently available and parseable.

Define:

```text
OPAQUE_CURRENT_TOKEN_HEADS(T)
UNAVAILABLE_SUPPORTED_CURRENT_HEADS(T)
READABLE_CURRENT_TOKEN_VALUES(T)
```

Any opaque or unavailable current head means v1 cannot claim complete understanding of current TOKEN value state.

### 24.6 Scope of degradation

A routable opaque TOKEN affects only its `TOKEN_ID`.

A routable opaque DEVICE affects only presentation/provenance for its `DEVICE_ID`.

Opaque-unscoped authenticated evidence blocks authoritative vault operations through `AUTHORITATIVE_VAULT_READY` but does not block explicit candidate use.

### 24.7 Integrity

Reappearing bytes for one durable `OBJECT_ID` must reproduce the same immutable routing record.

Detected corruption, global-ID inconsistency, or resolved cycles enters `LOCAL_CONTINUITY_UNKNOWN`.

Durable authenticated routing/evidence is not removed merely because synchronized bytes disappear.

---

## 25. Whole-state value and completeness semantics

For token `T`:

```text
H = KNOWN_CURRENT_TOKEN_HEADS(T)
O = OPAQUE_CURRENT_TOKEN_HEADS(T)
M = UNAVAILABLE_SUPPORTED_CURRENT_HEADS(T)
V = distinct READABLE_CURRENT_TOKEN_VALUES(T)
```

Interpretation:

```text
H empty:
    no known current TOKEN state

O non-empty:
    VALUE_INCOMPLETE_OPAQUE

O empty and M non-empty:
    VALUE_INCOMPLETE_UNAVAILABLE

O empty and M empty and |V| == 1:
    semantically unambiguous

O empty and M empty and |V| > 1:
    whole-state conflict
```

Opaque current state prevents a v1 client from asserting complete understanding even when all readable v1 heads agree.

Semantic-version number never orders state.

---

## 26. Lazy convergence

If every current TOKEN head is supported/readable and all complete values are equal, the client may leave the multi-head frontier unchanged.

A later meaningful edit naturally parents the full current frontier.

If any current head is opaque, v1 MUST NOT author merely to collapse the frontier.

A client that understands the opaque semantics may later author a descendant.

If a v1 client later learns a supported-readable descendant of the opaque node and all current heads become supported/readable, ordinary v1 semantics may resume.

---

## 27. Whole-state conflict, unavailable-state confirmation, and freshness

A v1 writer obtains explicit complete-state confirmation before authoring over supported current semantics that conflict or contain unavailable supported values.

A v1 writer MUST NOT author while:

```text
OPAQUE_CURRENT_TOKEN_HEADS(T) is non-empty
```

because it cannot represent/present the complete future-version current semantics.

This is a writer restriction, not a candidate-use restriction.

Confirmation binds the desired complete v1 value, exact current head IDs, and a monotonic confirmation-context epoch.

The epoch advances on current-head, value-availability, opaque-state, displayed provenance, discovery, and local-continuity changes.

An unpublished confirmation does not survive restart.

During a fold, exact local batch intermediates do not stale the active confirmation; any non-batch safety-relevant observation does.

---

## 28. Hidden or later-discovered history

A TOKEN records the exact parents its writer incorporated.

It does not prove that synchronization revealed every concurrent object.

A user may confirm current heads and create a later TOKEN. Discovery of another durable-valid TOKEN afterward does not retroactively invalidate the earlier action.

If the new object becomes a durably known ancestor of an existing current head, it is historical only.

If it remains incomparable:

- if all current values are available and equal, state is unambiguous;
- if all are available and differ, a whole-state conflict exists;
- if any current value is unavailable, current state is incomplete.

Later arrival of a previously missing parent object may resolve graph edges and change which durable known nodes are maximal, without changing any complete TOKEN value.

Because graph topology is durable, later disappearance of an already-known intermediate object file does not erase previously learned ancestry.

---

## 29. Missing ancestry and missing values are different

A TOKEN whose claimed parent is not yet in the durable known graph still contains a complete vault-authenticated value.

The child may be a known current head and its value may be ordinarily usable if every known current head value is available and unambiguous.

Missing ancestry therefore does not by itself block state use.

By contrast, a durable known current head whose complete object bytes are unavailable represents known semantic state whose value cannot be reconstructed.

That condition is `VALUE_INCOMPLETE` under Section 25 and blocks ordinary credential consumption.

Clients SHOULD clearly distinguish:

```text
ancestry incomplete:
    current value known, some history relationship unresolved

value incomplete:
    a known current state exists but its complete value is unavailable
```

The protocol does not reinterpret a child with a missing parent as a root. Its durable signed parent claim remains recorded.

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

## 31. DEVICE durable presentation graph

Durable DEVICE topology includes supported-valid and opaque-routable nodes.

Current DEVICE heads for one `DEVICE_ID` are maximal durable nodes under resolved same-device ancestry.

Supported provenance-verified v1 DEVICE heads may supply authenticated friendly names.

If any current DEVICE head is opaque, presentation state is incomplete for v1. The client SHOULD fall back to `DEVICE_ID` / known key fingerprint plus a future-version presentation warning.

A later supported v1 DEVICE descendant may restore readable current presentation.

Opaque DEVICE state affects presentation/provenance only and MUST NOT invalidate TOKEN state authority or credential generation.

---

## 32. Writer frontier rule

Before publishing a v1 TOKEN for `T`, require:

```text
AUTHORITATIVE_VAULT_READY
OPAQUE_CURRENT_TOKEN_HEADS(T) is empty
```

and parent exactly `KNOWN_CURRENT_TOKEN_HEADS(T)`.

Readable unambiguous supported state may be edited ordinarily.

Supported conflict/unavailable state requires Section 27 confirmation.

Opaque current TOKEN state blocks v1 authorship only for that token until upgrade/migration or a later supported-readable descendant moves the opaque node into history.

Unrelated tokens remain writable when `AUTHORITATIVE_VAULT_READY`.

Wide frontiers use Section 47's fold.

---

## 33. Operation freshness and publication linearization

Every credential-generation or authorship operation has a local freshness point.

### 33.1 Ordinary current TOTP generation

Immediately before ordinary use for `T`, recheck:

```text
AUTHORITATIVE_VAULT_READY
KNOWN_CURRENT_TOKEN_HEADS(T)
OPAQUE_CURRENT_TOKEN_HEADS(T)
UNAVAILABLE_SUPPORTED_CURRENT_HEADS(T)
READABLE_CURRENT_TOKEN_VALUES(T)
```

Ordinary use requires no opaque/unavailable current head and one unambiguous LIVE readable value.

### 33.2 Explicit candidate generation

Pin the exact candidate `OBJECT_ID`, supported-readable `TOKEN_VALUE`, `BASE_OPERATION_SAFE`, and current warning context.

Candidate use does not require `AUTHORITATIVE_VAULT_READY`; it may remain available under incomplete discovery, opaque current state, or opaque-unscoped evidence.

### 33.3 TOKEN authorship

Immediately before publication recheck authoritative readiness, exact current heads, no opaque current TOKEN head, supported-value conflict/availability, confirmation freshness, provenance verification, and persistence/resource state.

A changed frontier or newly opaque current head aborts/restarts the operation.

Final object bytes and durable routing records must be persisted before success is reported.

---

## 34. Durable local security memory

The durable known graph from Section 24 is the primary per-object local security memory.

It MUST be retained independently of the hostile synchronized vault namespace.

At minimum durable local security state includes:

```text
VAULT_BINDING
LOCAL_CONTINUITY_STATUS
KNOWN_TOKEN_NODE records
KNOWN_DEVICE_NODE records
OPAQUE_UNSCOPED records
```

An implementation MAY retain exact authenticated immutable object copies as a protected local recovery/cache layer, but this is not required.

The graph is append-only knowledge:

- a known valid node is not removed because synchronized bytes disappear;
- immutable parent claims are not rewritten;
- later node arrival may resolve/reject prior unresolved edges;
- graph indexes/current-head calculations are derived and may be rebuilt from durable records.

### 34.1 Security-memory storage boundary

The durable graph/security state MUST NOT be stored solely inside the hostile synchronized vault namespace.

It must reside in local application/security state whose rollback behavior is independent of ordinary vault synchronization, or be protected by an independent integrity/freshness mechanism.

### 34.2 Detected local security-memory rollback or reset

If the implementation detects, is informed of, or has independent evidence that durable local graph/security memory was restored from an older backup, deleted, reset, or rolled back, it MUST enter:

```text
LOCAL_CONTINUITY_UNKNOWN
```

unless an independent trusted mechanism proves no relevant knowledge was lost.

A complete rollback of all local application state that is indistinguishable from a fresh or internally consistent older installation cannot be detected by the vault protocol alone. Stronger local anti-rollback guarantees require platform/trusted monotonic state outside the rolled-back backup domain.

While `LOCAL_CONTINUITY_UNKNOWN`:

- prior local continuity/anti-rollback guarantees MUST NOT be claimed;
- current synchronized data MAY be inspected as fresh-client evidence;
- ordinary credential consumption and semantic authorship MUST remain blocked;
- missing graph knowledge MUST NOT be invented.

### 34.3 Baseline re-establishment

To leave `LOCAL_CONTINUITY_UNKNOWN` without trusted restored graph state:

1. perform a resource-complete scan of all currently available candidate semantic objects;
2. validate them normally;
3. build and durably persist supported-valid, opaque-routable, and opaque-unscoped records from currently available authenticated objects;
4. surface current conflicts, unavailable supported values, opaque future semantics, opaque-unscoped evidence, unreadable storage, and provenance warnings;
5. tell the user that previous local continuity knowledge is unavailable and fresh-client limitations apply;
6. obtain explicit acknowledgement establishing the newly built graph as the local continuity baseline;
7. durably leave `LOCAL_CONTINUITY_UNKNOWN`.

Baseline re-establishment does not itself author any synchronized TOKEN.

Conflicts/incomplete current values remain conflicts/incomplete after baseline establishment and are handled normally.

If the scan is resource-incomplete, or graph-integrity failure occurs while constructing the replacement graph, baseline re-establishment MUST NOT complete.

---

## 35. Explicit candidate credential use and convergence

An available candidate for logical token `T` is any supported-valid readable TOKEN with `TOKEN_ID=T` and `STATUS=LIVE`.

It may be current, concurrent, historical, selected while another current head is opaque/unavailable, or selected while discovery/unscoped future semantics are incomplete.

### 35.1 Candidate use

Candidate generation requires:

```text
CANDIDATE_USE_READY
```

and the exact selected supported-valid readable LIVE TOKEN.

Candidate use may continue despite incomplete discovery, opaque current TOKEN heads, or opaque-unscoped authenticated evidence.

UI must disclose all known uncertainty and state that the selected credential is not attested as uniquely current.

Candidate generation is explicit, non-authoritative, non-mutating, and pins exact `OBJECT_ID` + `TOKEN_VALUE`.

### 35.2 Whole-state convergence/reaffirmation

A v1 client may converge/reaffirm only when:

```text
AUTHORITATIVE_VAULT_READY
OPAQUE_CURRENT_TOKEN_HEADS(T) is empty
```

An older v1 client MUST NOT author over an opaque current future-version TOKEN.

### 35.3 Later understood descendant

If a supported-readable TOKEN `R` causally descends from opaque current head `C`, then C becomes historical.

When the resulting current frontier is fully supported/readable and otherwise unambiguous, ordinary v1 operation resumes.

---

## 36. Durable knowledge ordering

A newly validated semantic object MUST NOT be treated as durably known until its graph/security record is itself durable.

For newly authored local objects, the encrypted immutable object bytes MUST be durably published before, or atomically with, the durable graph insertion that allows the object to become current local knowledge.

If graph insertion succeeds before synchronized publication becomes durable, the client may remember an object that other clients cannot yet retrieve; implementations therefore SHOULD publish object bytes durably first and then durably record graph knowledge before reporting operation success.

For remotely discovered objects:

```text
validate exact object
        ↓
persist durable graph node
        ↓
only then allow that new knowledge to drive ordinary state use/writes
```

If persistence fails after validation, the relevant token/vault remains `KNOWLEDGE_PERSISTENCE_BLOCKED`.

Authenticated opaque-routable or opaque-unscoped future-version observations become safety-relevant only after their required durable record is persisted; until then operations that could ignore the learned authenticated information remain blocked.

A shared filesystem/database flush does not imply transactional atomicity unless the storage mechanism actually provides it.

---

## 37. Future semantic versions, future envelope families, and degraded interoperability

Authenticated future semantic versions inside `objects-v1/` are not automatically vault-wide fatal errors.

### 37.1 Routable future TOKEN inside the v1 envelope family

An `OPAQUE_ROUTABLE TOKEN` in `objects-v1/` is durably inserted into the TOKEN graph, participates in ancestry/current-head selection for its `TOKEN_ID`, and has no v1-readable `TOKEN_VALUE`.

While current, it degrades only that token. Explicit candidate use from readable supported LIVE TOKENs remains available. v1 semantic authorship is blocked only for that affected token while opaque current semantics remain. Unrelated tokens continue normal ordinary use and authorship.

### 37.2 Routable future DEVICE inside the v1 envelope family

An `OPAQUE_ROUTABLE DEVICE` in `objects-v1/` participates in the DEVICE graph for its `DEVICE_ID`.

It may make current friendly-name/presentation state unreadable but does not block TOKEN authority or credential generation.

### 37.3 Opaque-unscoped v1-family evidence

Authenticated `OPAQUE_UNSCOPED` evidence can arise only from an authenticated v1-family object whose scope cannot be determined by the old client.

It blocks `AUTHORITATIVE_VAULT_READY`, so ordinary current use and semantic authorship pause vault-wide. It does not block explicit candidate credential use under `CANDIDATE_USE_READY`.

### 37.4 Unknown sibling envelope families

A v1 client ignores unknown sibling storage namespaces for v1 semantic discovery.

For example, the existence of `objects-v2/` does not by itself prove a future Totipo version exists, create opaque semantic evidence, block ordinary/candidate operations, or alter the durable v1 graph.

This is intentional because the synchronization medium can fabricate arbitrary names/directories.

### 37.5 Rolling upgrades across envelope families

If a future family needs a different size/layout/encryption family, its own objects live outside `objects-v1/`.

To claim rolling compatibility with v1, the future writer also publishes the required authenticated v1-family compatibility assertion(s) into `objects-v1/`.

Old v1 clients observe only that compatibility projection.

A newer client may use the separate future-family representation as its authoritative richer state while maintaining the v1 compatibility graph for old clients.

### 37.6 No disappearance bypass

Once v1-family opaque routing/evidence has been durably learned, synchronized disappearance does not erase it.

The presence or absence of an unknown sibling family directory does not clear or create that evidence.

Only causal descendants, compatible reprocessing/upgrade, migration, or explicit continuity reset/re-establishment changes the durable v1 interpretation.

---

## 38. Ordinary and explicit candidate token consumption safety

Ordinary current TOTP generation requires:

```text
AUTHORITATIVE_VAULT_READY
KNOWN_CURRENT_TOKEN_HEADS(T) non-empty
OPAQUE_CURRENT_TOKEN_HEADS(T) empty
UNAVAILABLE_SUPPORTED_CURRENT_HEADS(T) empty
READABLE_CURRENT_TOKEN_VALUES(T) = exactly one distinct LIVE value
```

Candidate use may be offered when ordinary use is unavailable because of conflict, unavailable supported state, opaque future state, incomplete discovery, or opaque-unscoped evidence.

Candidate use requires `CANDIDATE_USE_READY` plus an exact supported-valid readable LIVE candidate.

Candidate use does not bypass local-continuity failure or failure to durably persist learned authenticated security information.

---

## 39. Freshness limitation

Observed state is relative to objects currently available to the client plus durable local security evidence.

No client can prove that the synchronization medium is not withholding a newer independent object that it has never seen.

A fresh client cannot distinguish a complete object set from a valid older subset with newer objects withheld.

Parent references prove only what the signer explicitly named as incorporated history; they do not prove global completeness.

Later discovery of hidden incomparable history may create a new whole-state conflict.

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

Newly generated secrets MUST contain at least 20 CSPRNG-generated bytes.

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

`OBJECT_VERSION` values are allocated by the published Totipo specification process for semantic grammars within an envelope family. r10 assigns `0x01`. All other values are unassigned by r10. Conforming implementations MUST NOT independently assign an unassigned value for interoperable/shared-vault use without a published Totipo specification allocating that value. r10 defines no private-use or experimental `OBJECT_VERSION` range.

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

## 47. Normal TOKEN write and staged bounded folds

A one-object TOKEN write uses exactly:

```text
PARENTS = KNOWN_CURRENT_TOKEN_HEADS(T)
```

and one complete resulting TOKEN value.

If current values conflict or any current value is unavailable, Section 27 explicit complete-state confirmation is required.

The writer sets `AUTHOR_TIME` under Section 20.1.

### 47.1 One-object write

If the complete current parent set fits:

1. snapshot exact `KNOWN_CURRENT_TOKEN_HEADS(T)`;
2. obtain any required confirmation;
3. choose one `AUTHOR_TIME`;
4. construct/sign/locally verify the complete TOKEN;
5. recheck the frontier, discovery state, persistence gates, and confirmation epoch immediately before publication;
6. durably publish encrypted object bytes;
7. durably insert the new TOKEN node into the known graph;
8. report success only after both are durable.

Once the node is durably inserted, graph ancestry naturally makes incorporated parents historical.

No accepted-head or superseded-ID bookkeeping exists.

### 47.2 Active multi-object fold

If the complete known current frontier does not fit one 1024-byte TOKEN under the Section 45 72-byte signature-reservation rule, the client performs a linear fold using ordinary TOKENs that all carry:

- the exact same confirmed complete state `S`;
- the exact same `AUTHOR_TIME`, captured once before the first batch object is signed.

Local session staging records:

```text
TOKEN_FOLD_BATCH {
    TOKEN_ID
    ORIGINAL_CURRENT_HEAD_IDS
    CONFIRMED_VALUE
    AUTHOR_TIME
    CONFIRMATION_EPOCH
    PUBLISHED_INTERMEDIATE_ID [...]
    LAST_STAGED_HEAD_ID?
}
```

For effective four-parent capacity:

```text
H1 H2 H3 H4  -> M1(S)
M1 H5 H6 H7  -> M2(S)
M2 H8 H9 H10 -> FINAL(S)
```

Each intermediate:

- is an ordinary complete authoritative TOKEN;
- is durably published and durably inserted into the known graph;
- may therefore be observed/used by other clients according to ordinary protocol semantics;
- is recorded as an exact locally batch-generated intermediate;
- does not by itself stale the initiating client's exact active batch confirmation;
- blocks unrelated same-token authorship on the initiating client until batch completion/abort.

Every later step parents the previous staged head plus as many still-unincorporated original current IDs as fit.

Finalization requires:

```text
X <=c FINAL
```

in the durable known graph for every original current head X.

Because every intermediate graph node remains durable knowledge even if synchronized bytes later disappear, no separate superseded-ID record is required.

### 47.3 Multi-object folds are not synchronized transactions

A fold is **not** an atomic distributed transaction.

Another client may observe and act on `M1` before `FINAL` exists.

This is safe because each intermediate:

- is itself a complete vault-authoritative TOKEN carrying state `S`;
- does not claim that every original head has already been incorporated;
- leaves uncovered original heads current until later fold objects causally incorporate them.

Only the initiating client's UI success reporting and confirmation staging are transaction-like/local.

Implementations MUST NOT invent hidden wire batch markers or assume other clients observe the fold atomically.

### 47.4 External changes and interruption

Any non-batch safety-relevant observation advances the confirmation epoch and aborts/stales the batch.

If publication stops partway:

- published intermediates remain ordinary durable known graph nodes;
- prior confirmation is not treated as completed local operation state;
- uncovered original heads remain current alongside staged history as derived from the graph;
- process restart discards batch/confirmation staging;
- the client recomputes current heads and obtains fresh confirmation where required.

The graph topology itself preserves all learned causal incorporation across later synchronized-file deletion.

---

## 48. Whole-state convergence/reaffirmation write

When current TOKEN values conflict or one/more known current values are unavailable and the user chooses one complete intended state:

```text
derive KNOWN_CURRENT_TOKEN_HEADS(T)
        ↓
show available candidates, unavailable-current warnings,
verified device context, and reported AUTHOR_TIME values
        ↓
obtain complete-state confirmation under §27
        ↓
construct complete desired TOKEN state S
        ↓
parents = all KNOWN_CURRENT_TOKEN_HEADS(T)
        ↓
one TOKEN under §47.1
or staged linear fold under §47.2-47.4
        ↓
durably publish object(s)
and durable graph node(s)
        ↓
FINAL becomes current by ordinary graph ancestry
```

No missing current object needs to reappear if its durable graph node is already known.

The user may copy the complete state of an available current candidate, use a historical candidate as a starting point, edit values using out-of-band knowledge, or construct a different complete state.

The protocol records the resulting authoritative TOKEN and its parent identities; it does not encode why the user chose particular field values.

---

## 49. DEVICE write and wide presentation frontiers

A v1 rename requires `AUTHORITATIVE_VAULT_READY` and no opaque current DEVICE head for the target `DEVICE_ID`, then uses the complete current supported provenance-verified DEVICE frontier.

If it fits one object, the new DEVICE parents every current verified DEVICE head and carries the selected display name.

If it does not fit, use an analogous staged linear fold:

- every fold object carries the same selected display name and the same `AUTHOR_TIME` captured for the rename action;
- first object references as many current heads as fit;
- later objects reference previous staged head plus additional original heads;
- every published assertion-valid DEVICE is durably inserted into the known DEVICE graph;
- exact locally staged intermediates do not stale their own rename selection;
- any external relevant DEVICE observation aborts/recomputes the selection;
- finalization requires every original verified current DEVICE head to be a durable known ancestor of FINAL.

Because durable DEVICE topology remains known after synchronized bytes disappear, no separate presentation superseded-ID bookkeeping is required.

If a current DEVICE value/name is unavailable, UI falls back to `DEVICE_ID`/fingerprint plus warning under Section 31.

DEVICE presentation incompleteness never changes TOKEN state authority.

---

## 50. Filesystem safety and family namespace isolation

Implementations SHOULD use bounded reads from stable file handles.

They MUST NOT rely solely on attacker-preservable metadata such as file size or timestamp as proof that known bytes are unchanged.

v1-family object discovery is confined to direct regular-file children of:

```text
objects-v1/
```

Implementations MUST NOT recurse into sibling `objects-*` namespaces when performing v1 discovery.

Where the synchronization root may contain attacker-controlled entries, implementations MUST prevent following untrusted symlinks, operating on special files as protocol objects, namespace escape through path traversal/rebinding, unsafe temporary-file redirection, and unintended blocking/side effects from hostile file types.

A name such as `objects-v2/` is not trusted future-version evidence.

A differently sized candidate inside `objects-v1/` is invalid current-family storage evidence, not authenticated opaque state.

Temporary publication files MUST use safe exclusive creation and no-follow/equivalent protections.

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

## 53. Security meaning of vault authentication, provenance, parents, and durable graph knowledge

Vault-root authentication establishes that semantic object bytes were created by a party possessing root-derived vault capabilities.

TOKEN value authority derives from this vault authentication plus intrinsic complete-state validity.

P-256 provenance is a separate attribution claim. Verified provenance does not grant additional protocol authorization; rejected/unresolved provenance does not erase TOKEN value authority.

A signed/vault-authenticated parent ID proves only that the child committed to that exact immutable identity.

For an established client, once compatible supported-valid or opaque-routable child/parent routing nodes are durably known, the resolved edge remains part of durable graph knowledge even if one or both synchronized files later disappear.

This durable graph memory prevents a hostile storage medium from making an established client forget previously authenticated causal relationships merely by deleting historical object files.

A fresh client has no such prior graph knowledge and remains subject to synchronization withholding.

Current-value availability is separate from topology knowledge:

```text
known current head
    !=
complete current value available
```

When a known current value is unavailable, the protocol preserves that fact and does not silently resurrect an older value.

Explicit candidate credential use under Section 35 is a user-directed availability escape hatch, not a change to current-state semantics.

`AUTHOR_TIME` is presentation/audit metadata only. It never creates or breaks causality and MUST NOT be used to choose a winner among concurrent assertions.

A party with `K_root` remains capable of authoring arbitrary new vault-valid TOKEN state; v1 does not provide membership authorization against such a party.

---

## 54. Core invariants

```text
K_root is the cryptographic identity of one v1 vault.

objects-v1/ is the exact storage namespace for the Totipo v1 envelope family.

Every valid object in objects-v1/ is exactly 1024 bytes.

OBJECT_VERSION versions semantics inside the v1 envelope family; it does not change
the family namespace, envelope size, object-ID/encryption construction, or frozen
routing contract.

A different envelope/storage family uses a different sibling namespace and is outside
v1 ordinary discovery.

Unknown sibling family names/files are not authenticated semantic evidence.

The frozen routing prefix lets older clients retain causal identity/topology for
future semantic versions that remain in objects-v1/.

Routable future TOKEN/DEVICE nodes participate in ancestry and current-head selection.

An opaque current TOKEN degrades only that token; unrelated tokens remain usable.

Opaque-unscoped authenticated v1-family evidence blocks authoritative operations
because scope is unknown, but explicit candidate credential use remains available.

A future envelope family claiming rolling compatibility with v1 publishes authenticated
v1-family compatibility assertions into objects-v1/.

A differently sized file in objects-v1/ cannot become opaque future evidence; without
a valid 1024-byte authenticated family envelope it is only invalid current storage.

Candidate use requires exact supported-valid readable LIVE material and never mutates
or reclassifies protocol state.

Resolved ancestry, not semantic version, timestamp, arrival order, namespace name,
or filename order, determines current heads.

Loss of semantic certainty should normally degrade capability rather than make
authenticated candidate material unusable.
```

---

## 55. Required conformance evidence for v1

Before v1 byte-level release-candidate freeze, executable evidence MUST cover at least:

### Bootstrap and root binding

- exact 87-byte `TOTIPO-VLT` bootstrap vectors;
- wrong magic/version/length rejected before Argon2id;
- Argon2id known-answer vectors;
- wrong-password and mutated-header/ciphertext/tag rejection;
- same-root rewrap recovery;
- optional remembered exact-VAULT fingerprint warning for same-root representation change;
- no-replace first creation;
- crash/restart establishment ordering;
- differing-root binding rejection.

### Storage-family namespace, canonical encoding, and object crypto

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
- malformed/non-curve DEVICE public key => DEVICE provenance rejected; TOKEN using its derived ID cannot verify;
- valid DER ECDSA signatures of multiple legal lengths and zero-length rejected-provenance fixture;
- malformed DER => provenance rejected, TOKEN state retained;
- mathematically invalid signature => provenance rejected, TOKEN state retained;
- randomized signatures for identical message/key are accepted;
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
- external observation during batch stales confirmation;
- every published fold TOKEN is durably inserted as a graph node;
- finalized multi-object fold has every original current head as a durable known ancestor of FINAL;
- deletion of synchronized intermediate bytes after finalization cannot erase durable fold ancestry or resurrect original heads;
- interrupted convergence batch leaves published intermediate nodes in the durable graph, uncovered original heads current as appropriate, and requires fresh confirmation after restart.

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

### Durable known-graph / missing-value behavior

- supported-valid and opaque-routable TOKEN nodes share one durable causal graph;
- opaque current TOKEN remains current while its value semantics are unreadable;
- routable opaque TOKEN affects only its TOKEN_ID;
- opaque-unscoped evidence blocks authoritative operations but not candidate use;
- later supported descendant of opaque current TOKEN can restore old-client ordinary semantics;

- startup/object-discovery state blocks ordinary current use and semantic authorship until READY;
- PROCESSING_INCOMPLETE may still permit explicit use of an already authenticated LIVE candidate with mandatory warning;
- newly observed candidate before operation freshness point is processed before completion;
- resource-incomplete discovery remains PROCESSING_INCOMPLETE;
- graph-node reappearance must match durable identity/topology/public-key/timestamp record;
- detected graph-record corruption enters LOCAL_CONTINUITY_UNKNOWN;
- resolved TOKEN/DEVICE cycle => graph-integrity failure, never zero-head/ordinary causal suppression;
- one OBJECT_ID reused across TOKEN/DEVICE or inconsistent immutable records => graph-integrity failure;

- assertion-valid TOKEN graph node persists after synchronized object deletion;
- persisted child+parent nodes retain resolved causality after either file disappears;
- known current head whose bytes disappear remains current with unavailable value;
- older available ancestor is not silently promoted to current;
- explicit candidate use may select an available current conflicting LIVE TOKEN;
- explicit candidate use may select an available current LIVE TOKEN while another current value is missing;
- explicit candidate use may select an older historical LIVE TOKEN when current values are unavailable;
- candidate use never mutates graph/current state;
- incomplete discovery, opaque current state, and opaque-unscoped evidence do not by themselves block candidate use;
- local continuity failure or knowledge-persistence failure does block candidate use;
- reaffirming TOKEN may parent a supported known current head whose value bytes are unavailable; v1 reaffirmation is prohibited while an opaque current TOKEN head exists;
- remote child of a locally known unavailable current head advances normally when learned;
- multi-object fold remains causally intact after synchronized intermediate file deletion;
- interrupted fold leaves durable intermediate graph nodes and requires fresh confirmation after restart;
- graph persistence failure after authenticated learning blocks ordinary use, authorship, and candidate use until durable persistence succeeds;
- detected local graph rollback/reset enters `LOCAL_CONTINUITY_UNKNOWN`;
- resource-complete baseline re-establishment rebuilds supported-valid, opaque-routable, and opaque-unscoped records and fails closed on graph-integrity errors;
- undetectable complete app-state rollback/fresh-install ambiguity is documented;
- graph growth is append-only and not protocol-bounded.

---

### DEVICE semantics

- root;
- rename;
- equal-valued concurrent names => unambiguous;
- differing names => presentation conflict;
- missing parent => verified current name may remain usable while ancestry is incomplete;
- wrong-device parent => rejected edge, child presentation assertion remains valid;
- token objects cannot become device causal parents;
- current DEVICE value unavailable => fingerprint/DEVICE_ID warning, not silent older-name fallback;
- durable DEVICE graph retains PUBLIC_KEY_X963 so future TOKEN provenance can still verify after synchronized DEVICE bytes disappear;
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
- opaque-unscoped evidence blocks authoritative operations but not candidate use;
- disappearance does not erase durable opaque routing/evidence;
- semantic version number never orders state.

### TOTP

- RFC 6238 SHA-1/SHA-256/SHA-512 vectors;
- 6/7/8 digits;
- period/time boundaries;
- secret length limits.

At least two independent implementations MUST consume the frozen v1 vectors before v1-rc1 is declared frozen.

---

## 56. Open work after r10

r10 retains the complete-state/durable-graph and opaque-routing architecture, and makes envelope-family evolution explicit through the fixed `objects-v1/` namespace plus authenticated compatibility projections from genuinely new future families.

Before v1-rc1:

1. extend/promote the executable semantic oracle to cover supported/opaque-routable graph nodes, opaque-unscoped evidence, scoped degradation, discovery, candidate use, staged folds, DEVICE presentation, timestamp, and continuity-baseline behavior;
2. complete remaining v1 crypto/bootstrap/TOTP conformance coverage;
3. continue adversarial review of state authority vs provenance, durable topology vs value availability, and parent semantic failure vs child TOKEN state;
4. verify durable graph persistence/integrity failures, discovery completeness, candidate-use under incomplete discovery, local continuity reset, and confirmation freshness across crash/restart and multi-client synchronization;
5. generate exact canonical `TOKEN` and `DEVICE` byte/crypto vectors including variable-length DER ECDSA signatures;
6. cross-verify P-256 provenance vectors in Java, Android Keystore, and Apple CryptoKit;
7. exercise 1006-byte envelope boundaries, four-parent maximum-field TOKENs, five-parent rejection, fourteen-parent maximum-display DEVICEs, fifteen-parent DEVICE folding, and linear wide-frontier folding;
8. test filesystem/crash ordering, graph-node durability, synchronized intermediate deletion, security-memory rollback/reset, and confirmation freshness across bounded convergence batches;
9. perform an external specification/security review before declaring v1 release-candidate freeze.

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

The security goals previously served by those mechanisms are addressed by complete vault-authenticated token state, whole-state conflict semantics, complete-frontier user confirmation, durable authenticated topology, explicit value-availability/candidate-use handling, and no-field-merge behavior.

---

## 58. Revision history

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
