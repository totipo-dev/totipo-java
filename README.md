# totipo-java

Java implementation of the Totipo vault protocol.

This repository targets **Totipo Vault Format v1**, design revision **r13**.
Development currently uses an exact pinned snapshot of the moving `v1-pre-rc` profile,
documented in [SPEC_PIN.md](SPEC_PIN.md). The implementation covers the M1.1–M1.3
routing, structural parsing, and cryptographic surfaces; it does not claim full protocol conformance.

## Toolchain

- Gradle 9.8.0, pinned by the checked-in Gradle Wrapper.
- JDK 25 is the default Nix shell and compiler toolchain JDK; Gradle runs on it.
- Core production Java is compiled with `--release 17` so the reusable library can
  remain compatible with Java 17 consumers, including the planned Android
  implementation boundary.
- Nix/direnv provide the local development environment.
- `fs-linux` explicitly uses the JDK 25 toolchain and `--release 25`.
- BC 1.86 is core's only external runtime dependency. JUnit and Jackson Core are test-only.

## Build

The Gradle Wrapper, Nix and Gradle lock files, and dependency-verification
metadata are checked in. A fresh clone can build directly without running
the bootstrap script.

With Nix:

```sh
nix develop --command ./gradlew build
```

Or with direnv:

```sh
direnv allow
./gradlew build
```

With JDK 25 already configured in `JAVA_HOME`, run `./gradlew build` directly. The first build
downloads the pinned Gradle distribution and dependencies if they are not cached.
Gradle toolchain auto-download is disabled; Nix/local JDK 25 supplies both compilers.

```sh
./gradlew clean test                              # whole build
./gradlew :core:clean :core:test                   # portable core only
./gradlew :fs-linux:test                          # filesystem integration
./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test
```

## Bootstrap maintenance

`bootstrap-m0.sh` is retained for explicitly regenerating the repository's
bootstrap files. Run it in the development shell, for example with
`nix develop --command ./bootstrap-m0.sh`. The script:

1. writes `flake.lock` when Nix is available;
2. generates a Gradle 9.8.0 Wrapper;
3. verifies the Wrapper JAR against Gradle's published SHA-256;
4. writes Gradle dependency locks;
5. writes SHA-256 dependency-verification metadata; and
6. runs the build.

Review any generated changes before committing, especially
`gradle/verification-metadata.xml`: newly recorded checksums come from the
artifacts downloaded during bootstrap.

## Repository shape

- `core` produces `totipo-core`: portable protocol/state/discovery semantics, Java 17 target,
  including the private security-memory journal and opaque-byte storage SPI.
- `fs-linux` produces `totipo-fs-linux`: Java-25 Linux adapters, depending on core.
  `NioDiscoverySource` remains a deliberately fail-closed fallback.
  `LinuxSecureDiscoverySource` provides authoritative secure discovery on reviewed
  Linux amd64 with libc `statx` and usable `/proc/self/fd`. It requires absolute
  UTF-8-representable roots and explicit FFM native-access permission. Classpath tests
  use `--enable-native-access=ALL-UNNAMED --illegal-native-access=deny`; core tests do not.
  Applications select an adapter explicitly and close its snapshots. Future module-path
  packaging should grant native access selectively to the filesystem artifact.
  `LinuxSecurityMemoryStorage.open(Path)` provides exclusive crash-durable local journal
  storage. The caller supplies a pre-existing per-vault directory: **the configured local
  security-memory directory must be app-local storage independent of the synchronized
  vault directory**. Durability requires a suitable local Linux filesystem/device honoring
  force/fsync; all processes must cooperate with advisory locking. Whole-journal rollback
  to an older valid copy remains potentially undetectable (pinned r13 §34.2).
  `LinuxDeviceProvenanceKeyStore.open(Path)` provides durable P-256 provenance-key
  custody in an explicit, pre-existing app-local per-vault directory. Its owner-only
  immutable key file is never synchronized; atomic no-replace creation needs no lock
  file. This is exportable filesystem custody, not hardware-backed protection.
  Core's provider-neutral SPI also permits future Android/non-exportable backends.
  Key availability does not advertise a DEVICE or enable TOKEN authoring.
  `LinuxV1ObjectPublicationStore.open(Path)` provides real immutable v1 object
  publication into exact `objects-v1/`, composing with core's initial DEVICE lifecycle
  and durable graph insertion. It binds the explicit existing synchronization root;
  opening leaves storage unchanged. First publication safely creates/binds the namespace
  lazily and fsyncs it and its parent. Exact 1024-byte objects use `O_TMPFILE`, byte
  read-back, no-replace `linkat`, file/directory fsync and final identity checks.
  This requires the supported local-filesystem durability boundary described below;
  it does not guarantee future availability against a synchronization actor. Orphans
  remain recoverable through discovery. No TOKEN writer or DEVICE rename/fold exists yet.
  `LinuxVaultBootstrapStorage.open(Path)` binds an explicit existing synchronized root
  and reads only exact canonical `vault`. Initial publication uses an unnamed owner-only
  `O_TMPFILE`, pre-link file fsync, no-replace procfd `linkat`, post-link inode fsync,
  and bound root-directory fsync. It requires usable procfs and a local filesystem
  supporting those primitives; arbitrary NFS, remote FUSE and cloud mounts are not
  covered. Unsupported operations fail without a named-temp or overwrite fallback.
  Core authenticates the staged inode and reopens canonical before establishing the
  local binding. Publication errors may leave canonical present for pending recovery.
  Close storage/staged handles explicitly; streams own separate descriptors and callers
  close them. Password replacement uses the same unnamed staging and adds a private
  hard link followed by `renameat2(RENAME_EXCHANGE)`, inode checks, file fsync and
  directory fsync. It requires Linux amd64/JDK 25, procfs, O_TMPFILE, hard links/linkat,
  libc/filesystem exchange support, and a local filesystem honoring these barriers.
  Both exchange names must exist; replacement never falls back to creating absent
  canonical. Core authenticates the result with the new password and unchanged
  root/binding, without modifying local security memory or semantic objects.
  The published inode has mode 0600. Interrupted/failed replacement can leave
  `.totipo-vault-rewrap-*.tmp` residue; only exact `vault` is authoritative.
  Residue can expose old/new offline password verifiers. Cleanup is best-effort:
  identity checking and unlinkat are separate syscalls, so a concurrent namespace
  actor can substitute the entry between them. Password rewrap cannot revoke
  historical copies retained by sync history, backups, hard links or copied files.
  Alternate-bootstrap recovery and fingerprint/rollback detection remain unimplemented.

The single r13 snapshot lives in `core/src/test/resources/totipo-spec`; `SPEC_PIN.md`
remains the repository-wide authority. Production JARs contain no test corpus.
