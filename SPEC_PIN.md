# Totipo specification pin

- Upstream: https://github.com/totipo-org/totipo-spec
- Exact upstream commit: `4623a7e1718e23504903096c92332597057bd8f0`
- Release/tag: no r18 tag or release exists; this is a committed revision pin.
- Snapshot UTC timestamp: `2026-10-03T01:03:41Z`
- Normative revision: `r18`
- Requirements profile (exact committed bytes; upstream status `moving-pre-rc`): `requirements/v1-pre-rc.json`
- Profile file SHA-256: `4c7954cd2b59aa0afbbe3c22080cadddf72135d884b186a671266c29d58418df`
- Local snapshot: `core/src/test/resources/totipo-spec/v1-pre-rc/`
- Vendored cases: **90**; upstream files: **97** (90 cases and 7 supporting files).

| Artifact | SHA-256 |
| --- | --- |
| `spec/totipo-vault-format-v1.md` | `8a357e75f3ddd92efa954fde2ffc9af33f40a2c2396d6afbf1d5de5f00bc4f8a` |
| `vectors/manifest.json` | `bd2b52adc05b26e09790f5f7367761b2b86ba3cf8d97d10ed187fcf7213fcf02` |
| `vectors/manifest.schema.json` | `f6dfef831f9b391ef8c9e675024b9cb9cb6cc352858c182439ee8847e55c3647` |
| `vectors/case.schema.json` | `d38618f53dcf0a558c389831e8838a07248066beff392812f3d277cc974e25c9` |
| `requirements/v1-pre-rc.json` | `4c7954cd2b59aa0afbbe3c22080cadddf72135d884b186a671266c29d58418df` |

The commit was selected by checking all five exact artifact hashes, its r18 revision,
and the 90-case manifest/profile contract. The snapshot contains only the normative
specification, moving requirements profile, manifest, schemas, vector format guide,
license, and manifest-listed case JSON files. `SNAPSHOT.sha256` covers each imported
upstream file, excluding itself, in sorted path order. Every physical case hash
matches the manifest and every required-case hash matches the profile.

Java derives semantics from the normative specification and language-neutral corpus, not from the Go implementation.

r18 changes application safety and conformance-scope documentation, with no portable
protocol behavior change from r17. All 90 ordered manifest case entries, physical
case bytes, case hashes, required-case entries, and expected outcomes are unchanged.
The implementation executes 90 / 90 cases without skips. Integrity tests establish
the exact pinned target; semantic consumers separately establish implementation
coverage. Scope claims and API qualifications are in README and API_DESIGN.md.
The selected commit repairs the stale profile hash in the first r18 commit; all
profile cross-pins match the exact committed artifacts. No upstream implementation
code is imported. See [the repin report](review/V1_R18_REPIN_REPORT.md).
