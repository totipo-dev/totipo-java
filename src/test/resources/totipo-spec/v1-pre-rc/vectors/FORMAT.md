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
expected outcome, normative status, and specification sections. IDs are stable.
Kinds distinguish exact bytes, negative parser inputs, and semantic/state cases.
The moving profile pins the complete manifest and per-case hashes. Reordering or
changing cases requires a reviewed profile update.

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

Each case begins with an established client and empty durable knowledge. Actions:

- `learn`: successfully persist the supplied immutable node and, if present,
  make its supported complete value available. Repeated IDs must match immutable
  metadata. `integrity_error: true` expects an ID conflict or resolved cycle.
- `persist-fails`: authenticated learning cannot persist; set the persistence
  safety gate. It cannot become authoritative known state.
- `disappear`: remove synchronized value availability while retaining knowledge.
- `discovery-incomplete`: set the discovery gate to `flag` (default false).
- `continuity-unknown`: set the continuity gate to `flag` (default false).
- `query`: compare every expected result field and assert that evaluating the
  query leaves graph state unchanged.

Queries name a token identity, exact candidate, and optionally a device identity.
Results expose sorted durable heads, whole-state completeness/conflict,
ordinary-use eligibility, authoring eligibility, explicit-candidate eligibility,
mandatory candidate warning, integrity failure, and optional DEVICE presentation.
`author` is eligibility for a fully confirmed write; this model does not implement
confirmation epochs or publication. Unavailable/conflicting supported frontiers
still require explicit whole-state confirmation under the specification.

Graph values contain all TOKEN_VALUE fields, excluding author, timestamp,
provenance and ancestry. DEVICE presentation uses only available verified heads.
These tests model security-memory semantics, not filesystem crash durability.
The timestamp fold case supplies a shared captured timestamp; it does not claim
to test a complete staged writer implementation.

## Deliberate fixture maintenance

Normal tests and CI never regenerate fixtures. For an explicitly reviewed corpus
change, from the repository root:

```sh
GOCACHE="$PWD/.direnv/go-build" go run ./conformance/cmd/totipo-vector-gen -root .
make check
```

The generator is tooling around the same Go consumer, not an independent protocol
implementation. It writes case files before adding entries to the manifest, then
writes the moving requirements profile. Existing full-object signatures are
reused and must still verify; changed signed inputs fail rather than silently
replace a fixture. Back up and review fixture changes when intentionally changing
signed inputs. Stable case IDs must not be reassigned to different requirements.

On first generation, full-object signatures are produced once using Go's
`crypto/ecdsa` CSPRNG-backed signer and verified locally. The two DER-length test
fixtures use offline length selection solely to exercise 70/72-byte verification.
That selection is not part of the writer and never influences writer parent sets.
The short-DER capacity rejection fixture uses one signature and its equivalent
low-S form; it is a deliberately forbidden writer shape that a reader can accept.
The actual writer helper reserves 72 bytes before a single signing attempt and
never retries to make a shape fit.

Graph expectations and reserved-size expectations are explicitly authored from
the specification, not obtained by running the semantic evaluator. First-generated
crypto bytes share implementation ancestry with their consumer; independent native
platform/live-implementation checks remain necessary before RC freeze.

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
opaque-unscoped IDs, authoritative readiness, and a query result from the existing
graph model. `INVALID_STORAGE` is unauthenticated/incorrectly sized storage evidence;
`INVALID` is failed supported semantic grammar. Neither becomes durable semantic
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

The in-memory model does not implement the live adapter's no-follow OS operations,
crash durability, or concurrent filesystem rebindings. Those remain work for the
first independent live consumer.
