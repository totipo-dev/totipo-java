# Totipo specification pin

- Upstream: https://github.com/totipo-org/totipo-spec
- Exact upstream commit on `main`: `1d42a481f230e0adbb89dbeaa936d3c956e70fdc`
- Snapshot UTC timestamp: `2026-09-29T22:48:30Z`
- Normative revision: `r17`
- Moving requirements profile: `requirements/v1-pre-rc.json`
- Profile file SHA-256: `ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e`
- Local snapshot: `core/src/test/resources/totipo-spec/v1-pre-rc/`
- Vendored cases: **90**; upstream files: **97** (90 cases and 7 supporting files).

| Artifact | SHA-256 |
| --- | --- |
| `spec/totipo-vault-format-v1.md` | `f8d2ab02c97e8ac54847048a06cb088359db982fec3f176fd473ce0f223d43cf` |
| `vectors/manifest.json` | `94fff22842573e15b254bb0653970761c15cf122192947a36fccc48344a84f08` |
| `vectors/manifest.schema.json` | `e7a5d8ec0392e0248ab867375b7c907a7ca1298595acdb14ecd3edcbe66df476` |
| `vectors/case.schema.json` | `d38618f53dcf0a558c389831e8838a07248066beff392812f3d277cc974e25c9` |
| `requirements/v1-pre-rc.json` | `ec65793e4734086cb79ad1bfbe96df4030c743b4b00d56bcdfa8cc90bfcbcb9e` |

The commit was selected by checking all five exact artifact hashes, its r17 revision,
and the 90-case manifest/profile contract. The snapshot contains only the normative
specification, moving requirements profile, manifest, schemas, vector format guide,
license, and manifest-listed case JSON files. `SNAPSHOT.sha256` covers each imported
upstream file, excluding itself, in sorted path order. Every physical case hash
matches the manifest and every required-case hash matches the profile.

Java derives semantics from the normative specification and language-neutral corpus, not from the Go implementation.

r17 is a threat-model / store-freshness clarification only. All 90 case JSON files
are byte-identical to the previous r16 pin. Java required no semantic production
changes for that revision transition. The r17 pin is unchanged. The implementation
now executes 90 / 90 portable corpus cases, with no portable categories deferred.
Integrity tests establish the pinned target; semantic consumers separately establish
implementation coverage. This accounting is not a release claim.
No upstream implementation code is imported.
