# totipo-java

Java implementation of the Totipo vault protocol.

This repository targets **Totipo Vault Format v1**, design revision **r10**.
Development currently uses an exact snapshot of the moving `v1-pre-rc` profile,
documented in [SPEC_PIN.md](SPEC_PIN.md). It contains no Totipo protocol
implementation yet and does not claim protocol conformance.

## Toolchain

- Gradle 9.8.0, pinned by the checked-in Gradle Wrapper.
- JDK 21 is the build/toolchain JDK.
- Production Java is compiled with `--release 17` so the reusable library can
  remain compatible with Java 17 consumers, including the planned Android
  implementation boundary.
- Nix/direnv provide the local development environment.
- M0 has no production dependencies. JUnit is test-only.

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

With JDK 21 already configured, run `./gradlew build` directly. The first build
downloads the pinned Gradle distribution and dependencies if they are not cached.

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

M0 stays deliberately single-project. Package/module boundaries should be
introduced when the implementation gives us a concrete need for them rather
than pre-designing a multi-project build.
