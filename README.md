# totipo-java

Java implementation of the Totipo vault protocol.

This repository targets **Totipo Vault Format v1**, design revision **r14**.
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

## Repository shape and storage boundary

- `core` produces `totipo-core`: portable protocol, state, discovery and journal
  semantics, compiled for Java 17.
- `fs-linux` produces `totipo-fs-linux`: Java 25 filesystem adapters, depending on core.
  Java NIO handles ordinary filesystem access and synchronized-state robustness.
  A minimal Linux native durability helper remains where the JDK lacks a documented
  containing-directory fsync primitive required by crash-safety semantics. It also
  explicitly fsyncs an existing journal before replay and exact-existing objects before
  acknowledging writer publication durability.

Under r14, synchronized contents may be malformed, stale, conflicting, missing,
replayed, replaced or withheld. The local OS, filesystem implementation,
mount/process namespace and same-privilege local processes are trusted for baseline
operation. Ordinary synchronization churn can make an operation unavailable or
incomplete; callers rescan, reopen or retry. Observed symlinks and special files are
excluded, reads remain bounded, and cryptographic authentication remains mandatory.

`NioDiscoverySource` enumerates only exact direct-child object filenames in
`objects-v1`. An absent namespace is empty; an observed non-directory is incomplete.
Observed regular candidates are read through NIO, at most 1025 bytes, then authenticated
by core. Discovery and canonical/key reads require no native-access permission.

`LinuxSecurityMemoryStorage.open(Path)` holds a lifetime advisory `FileLock` in a
pre-existing app-local per-vault directory independent of synchronized storage.
New lock/journal files have owner-only permissions; existing modes are preserved.
Initialization forces the journal and syncs its directory. Append/truncate force
before acknowledgement; ambiguous mutation poisons the handle until reopen. Existing
journals cross explicit file and directory fsync barriers before replay. All processes
must cooperate with locking. Whole-journal rollback to an older valid copy remains
potentially undetectable (r14 §34.2).

`LinuxVaultBootstrapStorage.open(Path)` reads only exact canonical `vault`, bounded
to 88 bytes. Initial publication writes a complete owner-only same-directory named
temp, forces it, and lets core authenticate it before `Files.createLink` installs the
canonical name without overwrite. Password rewrap uses `Files.move` with
`ATOMIC_MOVE` and `REPLACE_EXISTING`, after an ordinary regular-file precheck.
Both paths fsync the containing directory before core reopens/authenticates canonical.
Only the unchanged intended root and binding can produce success. Rewrap does not
revoke historical copies in provider history, backups or previously retained files.

`LinuxDeviceProvenanceKeyStore.open(Path)` keeps an immutable owner-only P-256 record
in an explicit app-local directory outside synchronized storage. It writes and forces
a private named temp, reparses/self-tests it, installs via no-replace hard link, forces
again, syncs the directory and reloads the fixed file. Group/other permissions are
rejected on load. This is exportable filesystem custody, not hardware-backed storage.

`LinuxV1ObjectPublicationStore.open(Path)` publishes exactly 1024 bytes to
`objects-v1`. Newly created namespaces cause a synchronization-root fsync. Complete
forced named temps are installed using no-overwrite hard links, forced again and
followed by containing-directory fsync. `ALREADY_PRESENT_EXACT` requires a bounded exact
read of an observed regular target, explicit file fsync, objects-directory fsync and an
exact reread. Only then may the writer proceed to durable graph insertion. Ordinary
discovery still learns authenticated current bytes without fsyncing synchronized objects.
Orphan objects remain recoverable through discovery.

Temps use implementation-private names that cannot match object filenames or canonical
`vault`. Cleanup is best effort. A crash may leave temps; they are never automatically
adopted. Custody temps contain sensitive private material and are created owner-only.

Native durability currently supports reviewed Linux amd64/x86-64 libc with only
`open`, `fsync` and `close` bindings. Applications requiring writes grant native access
with `--enable-native-access=ALL-UNNAMED` (or a future selective module grant).
Tests also set `--illegal-native-access=deny`; core needs no native access. Unsupported
hard links or atomic moves fail without an overwrite fallback. Crash durability requires
local filesystems/devices honoring force/fsync; arbitrary remote FUSE, NFS, cloud mounts
and broken hardware caches are outside that guarantee. Process-halt tests exercise
restart recovery, not physical power loss.

This cleanup reduces the native ABI, Linux-specific code, syscall bindings, platform
test matrix and audit surface, and avoids duplicating unnecessary machinery in future
Android/iOS backends. No external runtime dependencies were added: BC 1.86 remains the
only one. TOKEN authoring, DEVICE rename/fold, alternate-bootstrap recovery and
fingerprint/rollback detection remain deferred. The intentional first-DEVICE-before-TOKEN
conformance skip remains.

The single r14 snapshot lives in `core/src/test/resources/totipo-spec`; `SPEC_PIN.md`
is the repository-wide pin authority. Production JARs contain no test corpus.
