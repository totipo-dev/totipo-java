# Totipo specification pin

- Upstream: https://github.com/totipo-dev/totipo-spec
- Exact upstream commit on `main`: `54f38d13d62dc811c98489eb1867d63a9bef235a`
- Snapshot UTC timestamp: `2026-09-29T21:14:53Z`
- Normative revision: `r16`
- Moving requirements profile: `requirements/v1-pre-rc.json`
- Profile file SHA-256: `687faf7757de7c63da68c28889bf3d0976b1858f9647b67569e3d8dfafc59c56`
- Local snapshot: `core/src/test/resources/totipo-spec/v1-pre-rc/`
- Vendored cases: **90**; upstream files: **97** (90 cases and 7 supporting files).

| Artifact | SHA-256 |
| --- | --- |
| `spec/totipo-vault-format-v1.md` | `96f362d68251a801b2c433bd6435c0056d5b070bfe1258a12ae12bdf7bb7990e` |
| `vectors/manifest.json` | `d03821fa2a0c41145bd8b82c6ea46800ab1a847b50c92fb9996b3c585d6f0a33` |
| `vectors/manifest.schema.json` | `3b54847e7a21bacc7956406c0d79dc172a0fb6415e9eb9c0335a511c1987664a` |
| `vectors/case.schema.json` | `d38618f53dcf0a558c389831e8838a07248066beff392812f3d277cc974e25c9` |
| `requirements/v1-pre-rc.json` | `687faf7757de7c63da68c28889bf3d0976b1858f9647b67569e3d8dfafc59c56` |

The commit was selected by checking all five exact artifact hashes, its r16 revision,
and the 90-case manifest/profile contract. The snapshot contains only the normative
specification, moving requirements profile, manifest, schemas, vector format guide,
license, and manifest-listed case JSON files. `SNAPSHOT.sha256` covers each imported
upstream file, excluding itself, in sorted path order. Every physical case hash
matches the manifest and every required-case hash matches the profile.

Java derives behavior from the normative specification and language-neutral corpus, not from the Go implementation.

Phase 1 pins the r16 target but does not yet claim complete Java r16 semantic conformance.
Integrity tests establish the pinned target; they do not establish implementation
coverage of all semantic cases. No upstream implementation code is imported.
