# Portable v1 case contract

`manifest.schema.json` defines the manifest. `case.schema.json` defines case JSON.
All JSON integers are exact integers; consumers must preserve unsigned 64-bit
`author_time` without converting through floating point or signed date APIs.
All cryptographic `*_hex` strings and object IDs use lowercase hexadecimal.
The `input` object and `future.routing` use padded RFC 4648 base64 for binary
fields (`identity`, `author`, parents, secret, public key, signature), as indicated
in the schema. `null` parent arrays mean empty; a null signature means zero bytes.
This representation has no Go-specific serialized types.

Each manifest entry identifies one real case file, its SHA-256, category, kind,
expected outcome, normative status, and specification sections. Pre-RC IDs may be replaced with documented semantic changes.
Kinds distinguish exact bytes, negative parser inputs, and semantic/state cases.
The moving baseline profile pins the complete manifest hash and baseline case hashes. The manifest pins conditional case hashes too. Reordering or
changing cases requires a reviewed profile update.

## Case applicability

Every manifest entry declares exactly one strict applicability object:

```json
{"kind":"baseline"}
```

or:

```json
{"kind":"conditional","capability":"advisory-history"}
```

Unknown properties/capabilities reject. Baseline cannot include a capability;
conditional requires this recognized capability. `expected` remains a real outcome
when applicable. No SKIP or optional PASS state is used. The baseline profile's
required set equals only baseline manifest entries; every physical case file must
appear exactly once in the complete manifest.

`make conformance` runs baseline with no optional capability. To claim the optional
feature, use `make conformance-all` or `go run ./conformance/cmd/totipo-conformance -root . -capability advisory-history`.
Output separates baseline from `capability=advisory-history`; the reference model
explicitly declares support. No protocol feature-negotiation API or wire change is
implied. `make check` executes both baseline and full reference suites.

## Dispatch and full crypto

`dispatch` and `crypto` cases provide `root_hex`, exact `semantic_hex`, an expected
compatibility class, and a `crypto` diagnostic record. All such cases use the same
1024-byte envelope, including malformed semantic and synthetic future cases.

The diagnostic record provides the root-derived keys, object ID/key, nonce, AAD,
semantic length, padded plaintext, ciphertext, tag, and complete object bytes.
The consumer compares every intermediate, decrypts the committed object, verifies
its keyed identity, and then dispatches the exact authenticated semantics.

Supported exact objects also provide input field values. Full signed fixtures
add the fixed test private/public key, unsigned semantic bytes, signature input,
and canonical DER signature. Consumers verify the supplied signature. They must
not reproduce ECDSA signatures by signing the same message again. The fixture
private key is the public test scalar 1 and must never be used for real vaults.

Future cases provide `future.routing` and `opaque_tail_hex`. They use semantic
version 2, the frozen prefix, and deliberately malformed-as-v1 tail bytes. The
consumer rebuilds the prefix/tail bytes but never parses that tail as v1. Unknown
types and malformed future prefixes are authenticated opaque-unscoped evidence;
they are distinct from failed authentication or malformed supported bodies.

## Provenance, capacity, bootstrap

`provenance` cases carry a supported input, root, optional public key, and expected
`VERIFIED`, `REJECTED`, or `UNRESOLVED`. The corpus includes fixed valid 70-byte
and 72-byte DER signatures. Signature validity never determines TOKEN assertion
validity. Separate unit tests cover malformed signatures and invalid curve points.

`size` cases specify the complete shape, planned byte count, maximum parent fan-in,
and `FITS`/`FOLD` result. Planning always reserves 72 bytes. The short-DER case has
15 DEVICE parents and a 254-byte name: its fixed valid signature allows actual
bytes to fit, but its 1007-byte reserved size forbids that writer shape. Reader
acceptance and writer planning are deliberately distinct.

`bootstrap` cases provide password bytes, root, salt, nonce, Argon2id wrapping key,
header, full 87-byte record, and local vault binding. Empty and Unicode password
bytes are included. Salt/nonce/root values are fixed public fixture material.
Tests additionally exercise malformed inputs and authentication failures.

## TOTP known answers

`totp` cases execute the [RFC 6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B)
known answers, with the explicit 20/32/64-byte secrets used by Appendix A for
SHA-1/SHA-256/SHA-512. Each case carries source/notes, raw secret hex, the section
40 algorithm number, digits, period, `t0`, and six timestamp rows. Each row pins
Unix seconds, the integer counter, its exact eight-byte big-endian hex encoding,
and the zero-padded decimal code. The runner checks both counter derivation and
actual code generation. These fixtures use `t0=0`, period 30, and eight digits.
Expected codes are transcribed from the RFC, not computed by the generator.

## Graph steps

Graph cases are compact, language-neutral symbolic models. IDs such as `a`, `b`,
`T`, and `D` stand for already authenticated object and logical identities, not wire
hex values. `semantic_digest` names the exact immutable byte string represented
by the symbolic object. Learning is assumed to follow storage authentication and
intrinsic classification; the graph evaluator is not an alternate byte parser.

Each case begins with an empty accepted snapshot. `remember`, `history-lost`,
`history-clear`, and `cache-write-fails` require the conditional advisory-history
capability. Other actions operate on baseline protocol state. Actions:

- `learn`: accept supplied authenticated immutable evidence; repeated current IDs
  must agree. `integrity_error` expects a concrete contradiction or resolved cycle.
- `disappear` / `remote-unavailable`: subsequent observation excludes that object;
  remote reasons distinguish absent, unreadable, wrong-size, AEAD, padding, or ID failure.
- `remember`: optional advisory memory copies current IDs for regression warnings.
- `history-lost`: detected loss/corruption of previously retained/expected advisory memory; discard it, emit a diagnostic, retain current objects. Mere absence of the feature is not this event.
- `history-clear`: explicitly forget advisory memory/diagnostics without changing current graph state.
- `optional-cache-failure`: baseline hypothetical non-authoritative failure notification; cannot undo acknowledged publication and requires no cache implementation or diagnostic API.
- `cache-write-fails`: accept the object and expose a cache warning without blocking.
- `discovery-incomplete`: set the incomplete-view diagnostic to `flag`.
- `plan`: supply TOKEN node, complete desired value, intent, and confirmation `flag`;
  compare eligibility `success` and exact chosen `parents` against the snapshot.
- `publish`: supply acknowledgement `flag`; compare publication `success`. Ordinary
  plans survive later observations; confirmed conflicts recheck TOKEN context.
- `rename`: incorporate all supported DEVICE heads, including presentation-inert ones.
- `query` / `state-query`: compare complete current results without mutating state.

Results expose accepted heads, complete value/conflict state, ordinary authorship
eligibility, explicit candidate eligibility, optional `requires_confirmation`, and
optional warning expectations. `integrity_ok` describes concrete graph consistency,
not a global readiness predicate. Warnings never silently add nodes or values.
The timestamp fold case checks shared time, not a complete production fold writer.

## Deliberate fixture maintenance

Normal checks never generate fixtures. Fixed canonical bytes, signatures, signature
inputs, ciphertexts, IDs, VAULT bytes, and TOTP answers are immutable in r15. The old
monolithic generator was removed with its obsolete state semantics. Edit semantic
cases explicitly from the specification, review the before/after matrix, and update
manifest/profile pins only after checking the exact changed files. Do not derive
expected results from the Go evaluator just to make it pass. Independent consumers
remain necessary before RC freeze.

## Storage-family environments (r10)

`storage` cases separate a filesystem environment from authenticated semantic
fixtures and expected observations/state. `storage.root_hex` supplies the test
vault key, and `namespace_kind` describes the un-followed `objects-v1` directory.
`entries` use exact slash-separated paths relative to the configured synchronization
root and explicit kinds (`regular`, `directory`, `symlink`, `fifo`, `socket`,
`device`). No environment path is opened on the host filesystem.

A regular entry provides either `fixture_case` (an existing manifest envelope case),
`data_hex`, or `zero_bytes` (a bounded synthetic zero-filled file length). Omitted
content means empty bytes. Fixture references resolve only to hash-verified crypto
or dispatch cases in the same corpus and vault; recursive storage references,
missing IDs, duplicate paths, and mixed content descriptions fail verification.
Content readers are invoked only for exact v1-family candidates. Thus the runner
never decrypts or interprets ignored sibling representations.

`expect` records candidate observations and their classes, sorted learned IDs,
opaque-unscoped IDs, concrete graph integrity, and a query result from the existing
graph model. `INVALID_STORAGE` is unauthenticated/incorrectly sized storage evidence;
`INVALID` is failed supported semantic grammar. Neither becomes accepted semantic
knowledge. Query expectations are authored independently of the evaluator.

`objects-v1/` identifies the v1 envelope/storage family, while `OBJECT_VERSION`
identifies semantic versions within it. Every valid v1-family object is 1024 bytes.
Unknown sibling namespace names are not authenticated future-version evidence.
`objects-v2/` examples illustrate arbitrary future layouts, not a defined v2 format.

A future family claiming rolling compatibility publishes authenticated compatibility
assertions into `objects-v1/`. The shadow case reuses an existing authenticated
future TOKEN fixture and exercises scoped opaque degradation. The no-shadow case
learns nothing from the sibling and remains equivalent to its supported baseline:
that future family is not providing rolling-upgrade compatibility to v1 for that
state. Explicit candidate selection retains its existing mandatory warning even
on an ordinary supported baseline; sibling names add no warning or semantic block.

These in-memory environments model observed storage state and protocol classification.
They do not model local syscall-level TOCTOU races or crash durability.

Under r15, baseline v1 conformance does not require a live implementation to prove
immunity to a malicious same-privilege process racing namespace/type/inode changes
between individual filesystem calls. Static special-file/symlink handling, ordinary
synchronization churn, bounded reads, and protocol authentication remain required
as specified. Authoritative local VAULT/binding/private-key durability still requires platform evidence. Synchronized-object flushing is reliability guidance.

## Publication, binding, and provenance workflows

`publication` carries device/key identity and events. `advertise` supplies matching
identity, assertion validity, correct self-signature (`verified`), and local
`acknowledged` outcome; `publish-token` supplies its acknowledgement. Reported setup
success requires both. TOKEN-before-DEVICE visibility is allowed. These booleans
are construction/API outcomes, not mandatory runtime self-reader checks or fsyncs.

`local` trials model simple local API obligations. For `install`, `exact` targets
contain the intended 1024 abstract bytes (0x42 repeated), `different` contains 0x43,
and absent/symlink are explicit entry kinds. Exact ordinary-file bytes acknowledge
presence without an existing-file barrier; mismatched targets remain unchanged.
An unacknowledged absent-target attempt is UNKNOWN and may later be observed.
For `binding`, the derived anchor is 32 abstract 0x11 bytes; different is 0x12 and
corrupt is one byte. Authentication and authoritative durability outcomes are
explicit inputs. Absence allows first open, corruption requires recovery, mismatch
rejects. These abstract fixtures do not allocate or regenerate protocol bytes.

`signature-context` and `late-provenance` retain their fixed signed fixtures.
Context verification binds signatures to the vault. Late matching key arrival
updates UNRESOLVED to VERIFIED/REJECTED without changing complete values or ancestry.
Optional retained opaque bytes and their storage format are implementation choices;
there is no mandatory retention/reset case operation in r15.
