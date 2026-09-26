# totipo-java

Java implementation of the Totipo vault protocol.

This repository is currently at **M0: repository setup**. It intentionally
contains no Totipo protocol implementation yet. Protocol/spec pinning begins
in M1.

## Toolchain

- Gradle 9.8.0, pinned by the Gradle Wrapper after bootstrap.
- JDK 21 is the build/toolchain JDK.
- Production Java is compiled with `--release 17` so the reusable library can
  remain compatible with Java 17 consumers, including the planned Android
  implementation boundary.
- Nix/direnv provide the local development environment.
- M0 has no production dependencies. JUnit is test-only.

## First-time bootstrap

The archive deliberately does not contain generated lock files or a hand-made
Gradle Wrapper binary. Generate them from the pinned inputs on the machine
that will make the initial repository commit.

With Nix:

```sh
nix develop --command ./bootstrap-m0.sh
```

Or with direnv:

```sh
direnv allow
./bootstrap-m0.sh
```

The bootstrap script:

1. writes `flake.lock` when Nix is available;
2. generates a Gradle 9.8.0 Wrapper;
3. verifies the Wrapper JAR against Gradle's published SHA-256;
4. writes Gradle dependency locks;
5. writes SHA-256 dependency-verification metadata; and
6. runs the initial build.

Review the generated files before the first commit, especially
`gradle/verification-metadata.xml`: its initial checksums necessarily come
from the artifacts downloaded during bootstrap.

## Build

After bootstrap:

```sh
./gradlew build
```

## Repository shape

M0 stays deliberately single-project. Package/module boundaries should be
introduced when the implementation gives us a concrete need for them rather
than pre-designing a multi-project build.
