# totipo-java

Java implementation of the Totipo vault protocol.

This repository targets **Totipo Vault Format v1**, design revision **r14**.
Development currently uses an exact pinned snapshot of the moving `v1-pre-rc` profile,
documented in [SPEC_PIN.md](SPEC_PIN.md). The implementation covers the M1.1–M1.3
routing, structural parsing, and cryptographic surfaces; it does not claim full protocol conformance.

## Toolchain

- Gradle 9.8.0, pinned by the checked-in Gradle Wrapper.
- JDK 25 is the default Nix shell and compiler toolchain JDK; Gradle runs on it.
- Core and storage-nio production Java is compiled with `--release 17` so the reusable library can
  remain compatible with Java 17 consumers, including the planned Android
  implementation boundary.
- Nix/direnv provide the local development environment.
- `platform-linux` explicitly uses the JDK 25 toolchain and `--release 25`.
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
./gradlew :storage-nio:test                       # portable NIO, no native access
./gradlew :platform-linux:test                    # Linux integration
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

- `core` produces `totipo-core`: protocol/crypto/state only, Java 17, no filesystem.
- `storage-nio` produces `totipo-storage-nio`: portable synchronized-storage mechanics
  using Java 17 NIO, depending on core. No FFM, OS detection, native access, procfs or
  mandatory POSIX permissions. The configured provider must support required operations,
  including hard links and atomic replacement; unsupported operations fail without fallback.
- `platform-linux` produces `totipo-platform-linux`: Java 25 Linux durability and
  app-local security memory/private-key custody. It depends on storage-nio → core.
  Its native symbols are only `open`, `fsync`, and `close`.

Linux native code is not part of synchronized object parsing/discovery/publication logic;
it is a small platform durability/local-custody adapter.

Applications explicitly compose `NioVaultBootstrapStorage.open(root, LinuxDurability.open())`
and `NioV1ObjectPublicationStore.open(root, LinuxDurability.open())`. `StorageDurability`
has only `syncDirectory(Path)` and `syncExistingFile(Path)`. Newly written temporary
files are forced through their existing `FileChannel`. The injected capability handles
containing-directory durability and explicit fsync of pre-existing bytes, where
`FileChannel.force()` cannot supply the required contract. There is no default no-op,
provider registry, ServiceLoader or automatic platform selection. Discovery needs no
capability. Capability lifetime belongs to the caller; stores do not close it.

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

`NioVaultBootstrapStorage.open(Path, StorageDurability)` reads only exact canonical `vault`, bounded
to 88 bytes. Initial publication writes a complete same-directory named
temp, forces it, and lets core authenticate it before `Files.createLink` installs the
canonical name without overwrite. Password rewrap uses `Files.move` with
`ATOMIC_MOVE` and `REPLACE_EXISTING`, after an ordinary regular-file precheck.
The existing-destination behavior of `ATOMIC_MOVE` is provider-specific; this backend
requires and test-validates that capability on the host provider. No non-atomic fallback
is allowed. Both paths sync the containing directory before core reopens/authenticates canonical.
Only the unchanged intended root and binding can produce success. Rewrap does not
revoke historical copies in provider history, backups or previously retained files.

`LinuxDeviceProvenanceKeyStore.open(Path)` keeps an immutable owner-only P-256 record
in an explicit app-local directory outside synchronized storage. It writes and forces
a private named temp, reparses/self-tests it, installs via no-replace hard link, forces
again, syncs the directory and reloads the fixed file. Group/other permissions are
rejected on load. This is exportable filesystem custody, not hardware-backed storage.

`NioV1ObjectPublicationStore.open(Path, StorageDurability)` publishes exactly 1024 bytes to
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
Tests also set `--illegal-native-access=deny`; core and storage-nio need no native access.
`LinuxDurability.open()` is lazy: creating the capability does not require native access.
Each barrier checks availability and fails with IOException when access is denied.
A failed barrier can leave installed bytes, but cannot acknowledge durable success. Unsupported
hard links or atomic moves fail without an overwrite fallback. Crash durability requires
local filesystems/devices honoring force/fsync; arbitrary remote FUSE, NFS, cloud mounts
and broken hardware caches are outside that guarantee. Process-halt tests exercise
restart recovery, not physical power loss.

The synchronized-storage implementation now depends only on Java 17-compatible NIO/core
APIs and has no Linux-native dependency. Android compatibility still requires verification
against the chosen Android API/desugaring baseline and an Android-specific durability/local-custody
adapter. A future Android application can reuse core and supported storage-nio operations,
with Android durability facilities, app-private security memory, and Android Keystore
provenance custody. File-backed key custody is intentionally not generalized; core's
`DeviceProvenanceKeyStore` is already the portable boundary.

A future `totipo-desktop` Linux build assembles core, storage-nio, platform-linux, and
the desktop UI. Windows/macOS builds can reuse core/storage-nio with their own small
platform adapter. No platform-common or permission framework is introduced ahead of a
second concrete platform. Security-memory mechanics may eventually justify shared NIO
code with a local-private-storage policy, but Linux permissions/locking/durability remain
in platform-linux for now.

BC 1.86 remains the only external production dependency. Portable initial TOKEN authoring
is available internally. TOKEN publication may precede DEVICE advertisement; reporting
success waits for the matching valid, verified, durably remembered DEVICE advertisement.
General TOKEN edits/conflict handling, DEVICE rename/fold, alternate-bootstrap recovery
and fingerprint/rollback detection remain deferred. This is not yet an application API.

The single r14 snapshot lives in `core/src/test/resources/totipo-spec`; `SPEC_PIN.md`
is the repository-wide pin authority. Production JARs contain no test corpus.
