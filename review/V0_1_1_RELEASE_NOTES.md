## v0.1.1

### Highlights

Repin to Totipo Vault Format v1/r18; no portable protocol behavior change.

- Repinned to exact Totipo v1/r18 commit `4623a7e1718e23504903096c92332597057bd8f0`.
- No portable protocol behavior or corpus outcome changes.
- Clarified core/store/application conformance boundaries and documented r18 application responsibilities.
- Completed the CausalFact metadata/conformance audit, resolving the historical-metadata qualification.
- No Java semantic implementation change from the r18 repin/audit work.

### Compatibility

All 90 portable cases remain unchanged and pass. Wire format, crypto, TOKEN,
graph, fold and TOTP semantics are unchanged. Public API declarations and JVM
descriptors match v0.1.0. This is a patch alignment release; tests and packaging
remain compatible, with Maven coordinates advancing to 0.1.1 through `VERSION`.

### Scope

Core conformance covers the applicable protocol foundation and audited facade
operations documented in README and API_DESIGN; it is operation-scoped, with no
blanket facade certification. Qualified low-level NIO/core store conformance
remains limited to documented/tested local case-sensitive Linux provider
capabilities. Application conformance is not claimed.

Consuming applications remain responsible for empty-password confirmation,
orphan-vault warnings/confirmation, truthful state/conflict/tombstone/unavailable
presentation, delete-versus-erasure disclosures, password-rewrap security wording,
relevant-alternative disclosure and safe rendering of untrusted text.

### Validation

- 478 tests: 363 core and 115 NIO; zero failures, errors or skips. All 90 corpus cases execute.
- Clean normal and forced offline builds, strict dependency verification and both module-metadata/POM-only consumers pass.
- Snapshot integrity (3/3) and r18 profile integrity (1/1) pass explicitly; the 97-file checksum inventory validates.
- Java 17 production bytecode, JAR inventories and version-0.1.1 POM/module metadata pass publication checks.
- All 10 staged artifact SHA-256 hashes match across clean builds in the same environment, including two builds with caching disabled.

### Limitations / non-claims

Nix validation was unavailable (`nix` absent); Nix files are unchanged. There is
no universal filesystem or physical power-loss guarantee and no cross-platform
qualification beyond the existing Linux/provider evidence. No application
conformance certification, root-key migration/re-key support, secure deletion or
rollback protection is claimed. No new protocol feature or changed wire format.

See [the release-preparation report](V0_1_1_RELEASE_PREPARATION_REPORT.md) for
provenance, validation and artifact hashes. The final reviewed Java source commit
must be recorded by the human operator after committing and before release.
