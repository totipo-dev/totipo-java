# Totipo specification snapshot

This is an **exact snapshot pin of the moving v1 pre-RC profile**.
`v1-pre-rc` is not itself a frozen release profile or a frozen RC profile.

- Upstream repository: https://github.com/totipo-dev/totipo-spec
- Source branch: `main`
- Exact upstream Git commit: `618ced33487aebf768e908923abfd7ae34537a35`
- Snapshot date/time (UTC): `2026-09-27T03:29:02.019098+00:00`
- Protocol: Totipo Vault Format v1
- Protocol version: 1
- Design revision: r13
- Profile status: `moving-pre-rc` (moving pre-RC)
- Normative specification: `spec/totipo-vault-format-v1.md`
- Specification SHA-256: `513426313c7850b998239ed19a3d7399b32de203994931ae2d873516717ae228`
- Moving profile: `requirements/v1-pre-rc.json`
- Profile file SHA-256: `115dfd42fd6534aab7348c6bce9f4d8927f4823f16b419e0b6f85f3349edf108`
- Manifest: `vectors/manifest.json`
- Manifest SHA-256: `da289e75ccb2a8d73080cb8cc6ebcc2a6d39623edf2bfcbccce84b6b67dba8bd`
- Manifest schema: `vectors/manifest.schema.json`
- Manifest schema SHA-256: `59bdc9165b1c7e940031c447c2da640185774a6e4fd52fa0fee0b245061e0440`
- Case schema: `vectors/case.schema.json`
- Case schema SHA-256: `79e33b68bf948dcc332075827b791c8eb8e54d9cb27634dd59c0c6ac1fd95fd5`
- Required cases: 90
- Local snapshot: `src/test/resources/totipo-spec/v1-pre-rc/`
- Applicable upstream license: `LICENSE` in the snapshot (Apache-2.0).

## Authority and independence

Paths below are relative to the snapshot root, in descending authority:

1. `spec/totipo-vault-format-v1.md` is the normative protocol definition.
2. `requirements/v1-pre-rc.json` identifies the exact moving conformance target pinned by this Java snapshot.
3. `vectors/manifest.json` and its schemas define the portable case set and metadata.
4. Manifest-listed case files are the language-neutral byte/semantic fixtures.
5. `vectors/FORMAT.md` documents the portable case contract.
6. Other READMEs, review reports, tools, historical drafts, and implementation code are supporting material only.

Historical v0 artifacts are not an implementation target; v0 compatibility and
migration are out of scope. Java is intended to be the first independent live
implementation/interoperability consumer. Derive behavior from the normative v1
specification, portable contract, and language-neutral cases. Do not port or
translate the Go consumer, copy its parser/state-machine structures, or use its
behavior as an oracle or to resolve ambiguity. A later disagreement with Go is
evidence to investigate the specification/corpus, not a reason to automatically
make Java agree with Go. Fixed P-256/ECDSA fixture signatures must eventually be
verified as supplied, not reproduced by signing and comparing DER bytes.

## Integrity and updates

The vendored snapshot is intentionally immutable during ordinary builds/tests.
Tests use local files only and never fetch upstream or regenerate fixtures.
`SNAPSHOT.sha256` is local totipo-java provenance metadata, not an upstream Totipo
protocol artifact. It contains lowercase SHA-256 records sorted by relative path
for all 97 upstream files (90 cases plus seven supporting inputs), excluding
itself. The scoped `.gitattributes` rule disables Git line-ending conversion for
this directory so checkouts preserve the exact upstream bytes.

The JUnit integrity test hashes the source snapshot, rejects invalid paths and
uncovered files, independently pins the specification/manifest/schema/profile
hashes, and checks the profile hash recorded above. Import-time structured JSON
checks established profile identity, exact case-set equality, matching per-case
hashes, and all 90 physical case hashes. No JSON dependency or protocol parser is
needed for these cryptographic snapshot checks.

Updating the pin requires a separate explicit reviewed change. Fetch upstream
`main`, resolve a full commit SHA once, and perform every check and byte copy from
that commit. Check the intended profile identity, specification/manifest/schema
hashes, complete required-case set, matching profile/manifest case hashes, and
physical case hashes before import. Stop on discrepancies; do not regenerate
vectors or guess a normative correction. Atomically update the upstream commit,
spec/profile/manifest/schema hashes, vendored files, required-case set, and
integrity metadata/tests, including this document and a review report. Run clean
tests, the build, and cached-dependency tests with networking unavailable; review
byte equality and the complete diff. Never follow upstream changes automatically.
