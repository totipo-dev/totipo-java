# Totipo specification snapshot

This is an **exact snapshot pin of the moving v1 pre-RC profile**.
`v1-pre-rc` is not itself a frozen release profile or a frozen RC profile.

- Upstream repository: https://github.com/totipo-dev/totipo-spec
- Source branch: `main`
- Exact upstream Git commit: `e98dcc4cba2a97dc824f70128a24e9c9b20c3596`
- Snapshot date/time (UTC): `2026-09-26T06:05:55.880154+00:00`
- Protocol: Totipo Vault Format v1
- Protocol version: 1
- Design revision: r10
- Profile status: `moving-pre-rc` (moving pre-RC)
- Normative specification: `spec/totipo-vault-format-v1.md`
- Specification SHA-256: `8c93d6e05b0e19682d7875e011aba4961558ff7c606919006b98e3df30219b52`
- Moving profile: `requirements/v1-pre-rc.json`
- Profile file SHA-256: `d7b68ed799000a8c6449d3f114b8b1e62237db04b77400bf0a3c5e1123361b03`
- Manifest: `vectors/manifest.json`
- Manifest SHA-256: `031456a8b35633ab86c9a7c04c6f54ba00697b7577de9f43379ce4932c6bca38`
- Manifest schema: `vectors/manifest.schema.json`
- Manifest schema SHA-256: `59bdc9165b1c7e940031c447c2da640185774a6e4fd52fa0fee0b245061e0440`
- Case schema: `vectors/case.schema.json`
- Case schema SHA-256: `bab64fa1257ecc6cb0fdbd0aa0ceea223f93bf33be8031b1dcd0fd041aaf8af9`
- Required cases: 77
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
for all 84 upstream files (77 cases plus seven supporting inputs), excluding
itself. The scoped `.gitattributes` rule disables Git line-ending conversion for
this directory so checkouts preserve the exact upstream bytes.

The JUnit integrity test hashes the source snapshot, rejects invalid paths and
uncovered files, independently pins the specification/manifest/schema/profile
hashes, and checks the profile hash recorded above. Import-time structured JSON
checks established profile identity, exact case-set equality, matching per-case
hashes, and all 77 physical case hashes. No JSON dependency or protocol parser is
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
