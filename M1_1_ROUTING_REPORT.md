# M1.1 routing review

## 1. Scope

Implement bounded semantic-byte reads and only the frozen routing prefix. Envelope
size/authentication, object IDs, complete semantic validity, bodies, general TLV,
cryptography, provenance, graph/state semantics remain unimplemented. Input is
semantic plaintext, not a 1024-byte encrypted object. Authentication is a caller
precondition for treating a routing result as authenticated evidence.

## 2. Normative basis

Source: the r10 specification pinned in SPEC_PIN.md at
`e98dcc4cba2a97dc824f70128a24e9c9b20c3596`.

- §12, “Canonical semantic plaintext and frozen forward-compatible routing prefix”;
  §12.1 “Common routing prefix”; §12.2 “TOKEN routing prefix”; §12.3 “DEVICE routing prefix”.
- §12.4 “Opaque compatibility classes” and §15 “v1-family object reading and future-semantic dispatch”:
  future valid prefixes are OPAQUE_ROUTABLE, incompatible future prefixes and
  unknown types are OPAQUE_UNSCOPED. Supported routing is not SUPPORTED_VALID.
- §41 “Canonical TLV framing”: unsigned big-endian u16 tag and u16 length,
  followed by exactly length bytes; bounds-check the whole field before allocation.
- §42.1 “Common tags”, including “OBJECT_VERSION allocation”; §42.2 “TOKEN tags”;
  §42.3 “DEVICE tags”: version 1 is supported; type 1 is TOKEN, 2 is DEVICE.
  All other version bytes are unassigned/unsupported, including zero, not invalid
  merely for being unassigned. This reader does not allocate semantic versions.
- §43 “Parent encoding”: count 0..32, exact count of 32-byte parent IDs,
  strictly increasing unsigned lexicographic order (duplicates forbidden).

Exact layout (offsets count semantic bytes; every row includes a 4-byte header):

| Offset | Tag | Length/value |
|---|---|---|
| 0 | 0001 OBJECT_VERSION | 1 / u8 |
| 5 | 0002 OBJECT_TYPE | 1 / u8 |
| 10 | 0004 PARENT_COUNT | 2 / u16be, 0..32 |
| 16 + 36i | 0005 PARENT_ID | 32 raw bytes, i=0..n-1 |
| 16 + 36n | 0006 AUTHOR_TIME | 8 / u64be |
| 28 + 36n | 0101 TOKEN_ID or 0200 DEVICE_ID | 32 raw bytes |
| 64 + 36n (TOKEN only) | 0102 AUTHOR_DEVICE_ID | 32 raw bytes |

All listed framing, fields, positions/order, parent bounds/order are frozen across
semantic versions of this envelope family. Required prefix length is 100+36n for
TOKEN and 64+36n for DEVICE. Unknown types stop after the two identifying fields:
no family scope or presumed family layout can be inferred from their tail.
Malformed prefixes include missing bytes, wrong tags/order, wrong fixed lengths,
count above 32, missing/excess parents, and non-increasing parent IDs. Values of
identity/author IDs and all unsigned author times have no extra prefix restrictions.
No later body checks or envelope-size checks belong in this parser. A supported
malformed prefix is a malformed routing result; a malformed unsupported prefix is
unscoped with an explicit malformed/truncated reason. Failure before obtaining a
well-framed version is malformed, without guessing a semantic version.

## 3. Production design

All production types are package-private in `dev.totipo.format`; there is no
public API commitment, module descriptor, or additional Gradle project.

| Class | Responsibility |
|---|---|
| `ByteCursor` | Bounded synchronous reads of u8/u16be/u64be and copied bytes |
| `ByteCursor.TruncatedInput` | Intentional internal checked truncation signal |
| `RoutingPrefix` | Immutable version, type, parent IDs, author time, family identity and TOKEN author ID |
| `RoutingParser` | Exact ordered frozen-field parsing and routing classification |
| `RoutingParser.Result` | Outcome, optional complete prefix, and reason |
| `RoutingParser.Outcome` | Supported-v1 TOKEN/DEVICE routing, opaque-routable TOKEN/DEVICE, unscoped, malformed |
| `RoutingParser.Reason` | None, unknown type, malformed prefix, truncated prefix |

The cursor borrows the caller's array for the synchronous call; callers must not
mutate it concurrently. It never copies or interprets the tail. Each retained
byte field is copied, and model construction and accessors defensively copy
arrays including nested parent arrays. Parent lists are unmodifiable. The model
retains no body fields, validity/lifecycle state, envelope data, or inferred graph
state. DEVICE has no author-device field, represented by null.

Slice validation uses `length <= array.length - offset` after rejecting negatives
and out-of-range offsets, avoiding addition overflow. Reads compare the requested
length with the remaining slice before access/allocation. A field must have its
exact constant tag/width and available value before it is read. Parent allocation
is bounded by 32; no allocation uses an unchecked protocol length. Java argument
errors throw intentional ordinary exceptions. Truncation is caught and returned
as a classified result; partial prefixes are never exposed.

u8 is masked into int, u16 is assembled big-endian, and u64 is a positive
`BigInteger` covering 0..2^64-1. Parents use unsigned lexicographic comparison.

Supported outcomes are explicitly `SUPPORTED_V1_TOKEN` / `SUPPORTED_V1_DEVICE`,
not `SUPPORTED_VALID`. Unsupported known types with valid prefixes return
`OPAQUE_ROUTABLE_TOKEN` / `OPAQUE_ROUTABLE_DEVICE`. Unknown types return
`OPAQUE_UNSCOPED` with `UNKNOWN_TYPE`, without retaining a guessed identity.
Unsupported malformed prefixes return `OPAQUE_UNSCOPED` with a malformed or
truncated reason. Supported malformed prefixes and an unreadable version return
`MALFORMED`. Only successful family routing carries a complete `RoutingPrefix`.

Parsing stops immediately after TOKEN AUTHOR_DEVICE_ID or DEVICE DEVICE_ID for
all versions. There is no body inspection, TLV iteration, or envelope-size gate.
Thus a nonsensical v1 tail cannot invalidate future opaque routing, and a v1
prefix-only input can route successfully without being a valid complete object.

## 4. Vector infrastructure

`VectorCaseLoader` reads vendored classpath resources, selects category `routing`
from `manifest.json`, validates safe resource paths and unique IDs, and checks
case ID/expected value agreement with the manifest. Expectations come from the
case's `expected` field. `semantic_hex` supplies the actual parser input.

Test-only `com.fasterxml.jackson.core:jackson-core:2.18.2` supplies JSON tokenization.
A small immutable test tree exposes explicit string, exact BigInteger, object-field,
array, null, hex and base64 operations; no databind or custom JSON tokenizer is
used. Duplicate fields, trailing JSON, floating-point numbers, missing fields and
wrong types fail intentionally. Failure context includes the resource path and,
when selected through the manifest, the case ID. Hex requires even length and only
ASCII lowercase 0-9/a-f; no odd-length, uppercase, invalid or Unicode digit coercion.
Base64 comparisons enforce the contract's canonical padded encoding. Arrays
returned from decoded text are fresh, and fixtures are never rewritten.

`RoutingVectorTest` lives in the internal production package so the parser can
remain package-private; shared test loading stays in `dev.totipo.conformance`.
Successful fixtures compare every routing field against `input` or
`future.routing`, including parents and unsigned author time. Future fixture tail
bytes are also compared to `opaque_tail_hex` by the test, not the parser.

## 5. Vector results

Expected values below are the exact corpus values. PASS for SUPPORTED_VALID
means its **routing prerequisite only** passed, with all expected frozen fields;
M1.1 intentionally does not execute the complete dispatch/crypto contract.
Opaque labels here also presume authentication, which M1.1 does not perform.

| case ID | expected | actual | PASS/FAIL |
|---|---|---|---|
| v1.routing.device-future-opaque.001 | OPAQUE_ROUTABLE | OPAQUE_ROUTABLE_DEVICE | PASS |
| v1.routing.device-v1.001 | SUPPORTED_VALID | SUPPORTED_V1_DEVICE (routing only) | PASS |
| v1.routing.future-device-malformed-prefix.001 | OPAQUE_UNSCOPED | OPAQUE_UNSCOPED / MALFORMED_PREFIX | PASS |
| v1.routing.future-token-malformed-prefix.001 | OPAQUE_UNSCOPED | OPAQUE_UNSCOPED / MALFORMED_PREFIX | PASS |
| v1.routing.token-future-opaque.001 | OPAQUE_ROUTABLE | OPAQUE_ROUTABLE_TOKEN | PASS |
| v1.routing.token-v1.001 | SUPPORTED_VALID | SUPPORTED_V1_TOKEN (routing only) | PASS |
| v1.routing.unknown-type-unscoped.001 | OPAQUE_UNSCOPED | OPAQUE_UNSCOPED / UNKNOWN_TYPE | PASS |

## 6. Direct tests

- Every shortened form of each of the four valid routable vectors (328 inputs)
  yields an intentional truncated result without a complete prefix or exception.
- Direct family fixtures cover every truncation length for both families,
  versions 0/1/2/255, and counts 0/1/32; exact length succeeds. Even prefixes
  exceeding the complete envelope's capacity route here: capacity is later work.
- Empty reads, empty slices at the end, negative offset/length, excessive lengths,
  and overflowing offset+length combinations are covered. Failed reads do not
  advance, truncate, or see bytes beyond the selected slice.
- u8/u16 high bits, all-one u64 and 2^63 timestamps, high-bit version/type values,
  raw high-bit IDs, and unsigned parent comparisons are covered.
- Source mutation after parsing, mutation of returned arrays/nested arrays,
  constructor argument mutation, and attempts to mutate returned lists cannot
  modify the retained prefix.
- Every header byte of every frozen field is corrupted independently for both
  supported and future versions. Tests cover wrong family tags, count >32,
  count/multiplicity mismatch, duplicate and descending parents, and ordering
  differences in the last byte of an ID. Raw ID and author-time changes remain
  legal prefix values; versions and object types control dispatch without guessing.
- Both future families retain opaque routing with intentionally impossible v1
  tail lengths/incomplete framing; supported prefix routing likewise performs
  no body validation. Unknown types stop after the identifying fields even when
  their tail resembles a valid known-family prefix.
- Loader negatives cover broken/duplicate/trailing JSON, fractional numbers,
  absent/wrong-type fields, strict hex, unsigned integer preservation and fresh
  decoded byte arrays.

## 7. Dependencies

Production dependencies added: **none**. Production compile/runtime classpaths
remain empty according to `./gradlew dependencies`.

One testImplementation parser was added: `com.fasterxml.jackson.core:jackson-core:2.18.2`,
pinned by the version catalog. It provides established streaming JSON tokenization
without an object-mapping stack. The only additional runtime JAR is Jackson Core,
and only in tests. Gradle also selects Jackson BOM 2.18.2 as test-only metadata.

`gradle.lockfile` adds Jackson Core and its BOM to test compile/runtime only.
SHA-256 verification metadata adds the Core JAR/module, Jackson BOM/base/parent
and FasterXML oss-parent POMs. Resolution also requires JUnit BOM 5.10.2 metadata
referenced by Jackson's metadata; it is verified but does not replace the selected
JUnit 6.1.3 or add a runtime JAR. Existing verification entries are unchanged.
`settings-gradle.lockfile` is unchanged.

## 8. Build

Build JDK: 21; javac release target remains 17 with `-Xlint:all -Werror`.

| Command | Result |
|---|---|
| `./gradlew clean test` | PASS |
| `./gradlew build` | PASS |
| `./gradlew dependencies` | PASS; no production dependencies |
| `./gradlew --offline --no-daemon --no-build-cache --rerun-tasks clean test` | PASS; all 5 tasks executed |

Final offline run: 27 tests, zero failures/errors/skips, including all seven vector
cases and all three unchanged snapshot-integrity tests. Class-file major version
61 independently confirms the Java 17 target. `git diff --check` passes; the
vendored snapshot, pin, and integrity test have no diff.

The first build exposed Javadoc's refusal to document a source set with no public
or protected classes. The task now includes package-private types, preserving the
internal API boundary and generating documentation rather than disabling the task.
Javadoc reports missing-comment/@param warnings for internal members; compilation
and the final build pass. No integrity checks or compiler checks were weakened.

## 9. Diff summary

Added:

- `M1_1_ROUTING_REPORT.md` (this uncommitted review artifact)
- `src/main/java/dev/totipo/format/ByteCursor.java`
- `src/main/java/dev/totipo/format/RoutingPrefix.java`
- `src/main/java/dev/totipo/format/RoutingParser.java`
- `src/test/java/dev/totipo/conformance/VectorCaseLoader.java`
- `src/test/java/dev/totipo/conformance/VectorCaseLoaderTest.java`
- `src/test/java/dev/totipo/format/ByteCursorTest.java`
- `src/test/java/dev/totipo/format/RoutingParserTest.java`
- `src/test/java/dev/totipo/format/RoutingVectorTest.java`

Modified:

- `build.gradle.kts` (test dependency and internal Javadoc inclusion)
- `gradle/libs.versions.toml` (exact parser version)
- `gradle.lockfile` (test configurations only)
- `gradle/verification-metadata.xml` (new artifact hashes)

No vendored snapshot file, SPEC_PIN.md, or SpecSnapshotIntegrityTest changed.
All work remains uncommitted.

## 10. Issues / ambiguities

No normative/vector inconsistency was found. The corpus's SUPPORTED_VALID label
is broader than the milestone's routing-only scope, handled by an explicit test
projection rather than claiming full validity. The API reports an unreadable
version as MALFORMED and retains separate malformed/truncated reasons for
unsupported prefixes; these are local parser diagnostics, not new protocol states.
No newer specification snapshot or other implementation was consulted.
