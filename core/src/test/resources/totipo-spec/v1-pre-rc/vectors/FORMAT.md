# Portable v1/r16 case contract

`manifest.schema.json` and `case.schema.json` define strict JSON contracts.
Unknown members, mixed operation payloads, invalid enum values, and omitted
required expectations reject. JSON integers are exact; CLIENT_TIME must preserve
unsigned 64-bit values without passing through floating point or signed date APIs.
Cryptographic `*_hex` and object ID strings use lowercase hex. The `input` object's
binary identity, parents, and secret use padded RFC 4648 base64; arrays of parents
are explicit. Optional metadata is omitted when absent; an empty string or numeric
zero is a present value. JSON is a fixture representation, not the protocol wire.

Every physical case appears once in the manifest with ID, category, kind (`bytes`,
`negative`, or `semantic`), sections, expected outcome, path, and SHA-256. The moving
profile requires exactly that set and pins both schemas, manifest, and specification.
Pre-RC changes need reviewed case classifications. No capability or SKIP mechanism
exists in this corpus.

## Byte cases

`crypto` cases provide root, canonical semantic plaintext, input field values,
and all crypto intermediates: derived ID/key roots, OBJECT_ID/key, nonce, AAD,
semantic length, padded plaintext, ciphertext, tag, and complete 1024-byte object.
The consumer compares every intermediate, opens the committed bytes, checks the
keyed identity, and validates/re-encodes the exact TOKEN.

`dispatch` negative cases use genuinely authenticated envelopes over deliberately
invalid semantic plaintext. Expected `INVALID` means no TOKEN state, regardless of
authentication. Wrong-size and failed-AEAD storage cases remain separate from invalid grammar.

`post-aead` negative cases carry a valid canonical `semantic_hex` P, a filename
`object_id`, exact 1008-byte `encryption_plaintext_hex`, full 1024-byte `object_hex`,
and a named `defect`. The three defects are nonzero padding, keyed-ID mismatch,
and declared semantic length 1007. The generator directly authenticates the
malformed plaintext with the filename-derived key/nonce/AAD; it does not weaken
the canonical writer API. For keyed-ID mismatch, the filename deliberately differs
from HMAC(K_id, P), and encryption uses that different ID consistently. This is
not a collision fixture.

The consumer first proves the committed bytes pass raw GCM authentication and
contain the claimed isolated defect. It then requires the normal strict reader to
reject them and storage observation to yield `INVALID_STORAGE` with no semantic
state. A failed AEAD tag does not satisfy a post-AEAD case. This checks distinct
physical-size, authentication, length, padding, keyed-ID, and grammar boundaries.
Unit tests additionally exercise malformed names, wrong roots, and fixture tampering.

`bootstrap` provides exact password/root/salt/nonce, Argon2id wrap key, header,
87-byte record, and VAULT_FINGERPRINT. Rewrap uses the same root with a different
password/salt/nonce and retains the fingerprint. Fixed random values are public
test material and must never be reused by live creation or rewrap.

`totp` preserves the RFC 6238 Appendix B known answers for SHA-1/256/512, each with
six rows. It includes the algorithm-specific ASCII secret, time, counter, exact
u64be counter bytes, and decimal code. Expected codes come from the RFC, not the
generator. The linked source in each case records their origin.

## Graph and fold cases

`graph` steps start with an empty observed set. `add` supplies an already validated
TOKEN fact; `remove` models loss from observation; `evaluate` compares head IDs and complete head records, distinct values,
unresolved IDs, and conflict. Each `head_objects` record retains parents, value, and optional
client metadata exactly while that object is represented; it is not merged when
semantic values are equal. This adds no persistent retention requirement. IDs and
complete values are symbolic.
`canonical` labels the exact immutable plaintext represented by a fact. Repeated
IDs with differing labels exercise defensive identity failure. Cycles/SCCs and
same-ID cases do not claim encrypted collision fixtures. A failed identity is
excluded for that model evaluation context, without a persisted recovery state.

Expected results are written from the specification independently of the Go graph
evaluator. Cycles retain all members as current until a strict descendant supersedes
the group; unavailable intermediates never supply inferred paths.

`fold` supplies one complete `token` operation, sorted original 32-byte IDs,
modeled stage IDs, and exact sorted parent sets per stage. First stage takes four originals, later stages previous fold
plus up to three originals. Separate tests construct real encrypted stages, check
complete-value preservation, and inject later-stage failure. Every stage preserves
the operation’s exact CLIENT_NAME and CLIENT_TIME presence and values, including absence, present-empty name, and numeric zero.

## Storage and workflow cases

`storage` supplies root, namespace kind, and exact relative paths with observed entry
kinds and optional bytes/read failures. No case path is opened on the host filesystem.
The expected class sequence describes candidate observations: `SUPPORTED_VALID`,
authenticated invalid grammar `INVALID`, or size/authentication failure
`INVALID_STORAGE`. Ignored entries produce no class. Read/namespace errors are
reported by the diagnostic flag; processing may still retain validated objects.

`workflow` models backend outcomes for `publish`, `create`, or `replace`. Creation
and replacement operate on exact lowercase `vault`; uppercase conceptual VAULT
refers to its representation, never a pathname alias.
The replacement workflow's `kind` describes the newly observed canonical entry;
only `regular` permits comparison/replacement. A namespace observation accepts only
`directory`; wrong types produce diagnostics and are not traversed. These observed
entry-type rules do not mandate host race-hardening primitives.

`durable` means the backend believes its required persistence work succeeded;
`complete` means complete replacement/bootstrap bytes were constructed separately.
Exact-existing publication succeeds with no new durability work, while non-exact
existing entries remain untouched. Ambiguous failure returns `FAILED` without
asserting absence. Parent availability and orphan-object presence are supplied
independently and deliberately do not gate publication or creation.

Replace compares freshly observed bytes to `base_hex`. These workflow byte strings
are abstract representations, not bootstrap crypto fixtures. Unequal bytes mean
`STALE`; inability to compare means failure. This models compare-before-replace,
not atomic CAS, real filesystem effects, persistent pending state, or crash proof.

## Deliberate maintenance

Normal checks never write cases. The explicit generator is:

```sh
go run ./conformance/cmd/generate-vectors -root .
```

It regenerates r16 fixtures and exact moving pins, preserves RFC TOTP files, and
removes physical cases no longer in its declared corpus. Review its inputs and all
before/after bytes. It uses the Go crypto primitives shared with the consumer;
this is reproducibility evidence, not an independent cryptographic implementation.
Use independent implementations before RC freeze. The existing Unicode bootstrap
password is retained as an explicit source fixture.
