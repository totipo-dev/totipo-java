package dev.totipo.format;

import static dev.totipo.format.DiscoveryFixtures.*;
import static dev.totipo.format.DurableKnowledgeState.PersistenceResult.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DiscoveryTest {
    @Test
    void ignoredKindsAndNamesNeverInvokeContentReaders() throws Exception {
        var a = fixture(TOKEN); var source = new DiscoveryFixtures();
        var forbidden = new Entry("regular", () -> { throw new AssertionError("Ignored content read"); });
        for (String name : List.of("", "A".repeat(64), "a".repeat(63), "a".repeat(65),
                " " + "a".repeat(63), "ａ".repeat(64), "a".repeat(64) + ".tmp",
                "../objects-v1/" + a.id().filename(), "nested/" + a.id().filename(),
                "prefix-" + a.id().filename(), a.id().filename() + "\n")) {
            source.entries.put("objects-v1/" + name, forbidden);
        }
        for (String kind : List.of("directory", "symlink", "fifo", "socket", "device")) {
            source.entries.put("objects-v1/" + String.format("%064x", kind.hashCode()), new Entry(kind, forbidden.content()));
        }
        source.entries.put("objects-v2/" + a.id().filename(), forbidden);
        var result = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        assertTrue(source.reads.isEmpty());
        assertTrue(result.observations().isEmpty());
        assertEquals(DiscoveryState.READY, result.discoveryState());
    }

    @Test
    void cycleFromCommittedInsertionIsSeparateFromScanCompleteness() throws Exception {
        var a = fixture(TOKEN); var b = fixture(CHILD);
        var source = new DiscoveryFixtures(); source.put(a);
        var baseline = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        var original = (KnownTokenNode) baseline.knowledge().record(a.id());
        // Seed corrupt local routing that claims the actual child's ID as its parent.
        var seed = new KnownTokenNode(a.id(), 1, SemanticStatus.SUPPORTED_VALID,
                original.tokenId(), List.of(b.id()), original.authorDeviceId(), original.authorTime());
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(seed, COMMITTED).state();
        source.entries.clear(); source.put(b);
        var result = run(source, a.root(), state);
        assertEquals(2, result.knowledge().size());
        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE, result.topology().integrity());
        assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN, result.knowledge().continuity());
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertFalse(new VaultReadiness(result.knowledge(), result.discoveryState()).baseOperationSafe());
    }

    @Test
    void ordinaryDiscoveryDoesNotReclassifyRetainedUnscopedEvidence() throws Exception {
        var a = fixture(TOKEN); var source = new DiscoveryFixtures(); source.put(a);
        // Trusted M2.0 integration seam, not an authenticated prior interpretation.
        var seed = new OpaqueUnscopedRecord(a.id(), new SecurityBytes(a.bytes(), 1024));
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(seed, COMMITTED).state();
        var result = DiscoveryCoordinator.discover(source, a.root(), state, o -> {
            throw new AssertionError("Reclassification needs a dedicated future workflow");
        });
        assertEquals(seed, result.knowledge().record(a.id()));
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertTrue(result.readable().evidence().isEmpty());
    }

    @Test
    void wrongSizeCannotInvokeEnvelopeReader() {
        var classifier = new ObjectDiscovery((name, bytes, root) -> { throw new AssertionError("AEAD invoked"); });
        for (int length : new int[]{0, 1, 1023, 1025, 2000}) {
            var result = classifier.classify(new ObjectId(new byte[32]), new byte[length], new byte[32]);
            assertEquals(ObjectDiscovery.Classification.INVALID_STORAGE, result.classification());
            assertEquals(ObjectDiscovery.Detail.WRONG_LENGTH, result.detail());
            assertNull(result.authenticated());
        }
    }

    @Test
    void boundedReadConsumesOnlyRequiredBytesAndStopsOnNoProgress() throws Exception {
        for (int length : new int[]{0, 1023, 1024, 1025, 10_000_000}) {
            var channel = new CountingChannel(length, 97);
            assertEquals(Math.min(1025, length), BoundedObjectRead.read(channel).length);
            assertEquals(Math.min(1025, length), channel.consumed);
            assertEquals(length <= 1024, channel.sawEof);
        }
        var stalled = new CountingChannel(1024, 0);
        assertThrows(IOException.class, () -> BoundedObjectRead.read(stalled));
        assertEquals(1, stalled.calls);
    }

    @Test
    void lateAdditionBelongsToNextPass() throws Exception {
        var a = fixture(TOKEN); var b = fixture(CHILD);
        var source = new DiscoveryFixtures(); source.put(a);
        DiscoverySource changed = () -> { var fixed = source.snapshot(); source.put(b); return fixed; };
        var first = run(changed, a.root(), DurableKnowledgeState.establishedEmpty());
        assertEquals(List.of(a.id()), first.observations().stream().map(ObjectDiscovery.Observation::id).toList());
        assertTrue(first.resourceComplete());
        var second = run(source, a.root(), first.knowledge());
        assertEquals(2, second.observations().size());
        assertEquals(2, second.knowledge().size());
        assertEquals(2, second.readable().evidence().size()); // Historical root remains readable.
        var token = second.readable().get(a.id()).tokenId();
        assertEquals(java.util.Set.of(b.id()), second.topology().currentTokenHeads(token));
        var policy = policy(second, token);
        assertTrue(policy.candidateUse(policy.candidates().get(a.id())).warnings()
                .contains(CandidateWarning.CANDIDATE_HISTORICAL));
    }

    @Test
    void disappearanceAndReadFailureRetainFrozenCandidateAndKnowledge() throws Exception {
        var a = fixture(TOKEN);
        var source = new DiscoveryFixtures(); source.put(a);
        var initial = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        for (boolean removed : List.of(true, false)) {
            source.put(a);
            DiscoverySource changed = () -> {
                var fixed = source.snapshot();
                if (removed) { source.remove(a.id()); }
                else { source.entries.put("objects-v1/" + a.id().filename(), new Entry("regular", null)); }
                return fixed;
            };
            var result = run(changed, a.root(), initial.knowledge());
            assertEquals(ObjectDiscovery.Classification.UNAVAILABLE, result.observations().get(0).classification());
            assertFalse(result.resourceComplete());
            assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
            assertEquals(initial.knowledge().records(), result.knowledge().records());
            assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN, result.knowledge().continuity());
            assertTrue(result.readable().evidence().isEmpty());
            var token = initial.readable().get(a.id()).tokenId();
            assertEquals(TokenOperationPolicy.Reason.DISCOVERY_INCOMPLETE, policy(result, token).ordinaryUse().reason());
            // Explicit separately trusted exact evidence, bound to THIS graph; not inherited by scanner.
            var trusted = new CurrentReadableValues(result.topology(), initial.readable().evidence());
            var policy = new TokenOperationPolicy(new VaultReadiness(result.knowledge(), result.discoveryState()),
                    result.topology(), token, trusted);
            assertTrue(policy.candidateUse(policy.candidates().get(a.id())).eligible());
        }
        source.remove(a.id());
        var absent = run(source, a.root(), initial.knowledge());
        assertTrue(absent.resourceComplete());
        assertEquals(DiscoveryState.READY, absent.discoveryState());
        assertEquals(initial.knowledge().records(), absent.knowledge().records());
        assertTrue(absent.readable().evidence().isEmpty());
    }

    @Test
    void currentBytesAfterFreezeDetermineClassification() throws Exception {
        var a = fixture(TOKEN);
        for (int length : new int[]{7, 1024, 1025}) {
            var source = new DiscoveryFixtures(); source.put(a);
            var result = run(() -> { var fixed = source.snapshot(); source.put(a.id(), new byte[length]); return fixed; },
                    a.root(), DurableKnowledgeState.establishedEmpty());
            assertEquals(ObjectDiscovery.Classification.INVALID_STORAGE, result.observations().get(0).classification());
            assertTrue(result.resourceComplete());
            assertEquals(DiscoveryState.READY, result.discoveryState());
        }
    }

    @Test
    void incompleteEnumerationAndZeroProgressCannotBecomeReady() throws Exception {
        var a = fixture(TOKEN);
        var source = new DiscoveryFixtures(); source.put(a);
        source.issue = DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE;
        var partial = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        assertEquals(1, partial.knowledge().size());
        assertFalse(partial.resourceComplete());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, partial.discoveryState());
        assertEquals(source.issue, partial.snapshotIssue());
        var failed = run(() -> { throw new IOException("enumeration"); }, a.root(), partial.knowledge());
        assertFalse(failed.resourceComplete());
        var stalled = new CountingChannel(1024, 0);
        var zero = run(() -> new DiscoverySource.Snapshot(List.of(new DiscoverySource.Candidate(a.id(), () -> stalled)),
                DiscoverySource.SnapshotIssue.NONE), a.root(), partial.knowledge());
        assertFalse(zero.resourceComplete());
        assertEquals(ObjectDiscovery.Classification.UNAVAILABLE, zero.observations().get(0).classification());
        assertFalse(stalled.isOpen());
    }

    @Test
    void persistenceRequiredForEveryNewClassButNeverForExactRepeat() throws Exception {
        for (String name : List.of(TOKEN, "v1.crypto.device-root.001", FUTURE,
                "v1.crypto.future-device-opaque.001", "v1.routing.unknown-type-unscoped.001")) {
            var a = fixture(name); var source = new DiscoveryFixtures(); source.put(a);
            var attempts = new AtomicInteger();
            var failed = DiscoveryCoordinator.discover(source, a.root(), DurableKnowledgeState.establishedEmpty(), o -> {
                attempts.incrementAndGet();
                if (o.record() instanceof OpaqueUnscopedRecord unscoped) {
                    assertArrayEquals(a.bytes(), unscoped.exactObjectBytes().bytes());
                }
                return FAILED;
            });
            assertEquals(1, attempts.get());
            assertEquals(0, failed.knowledge().size());
            assertTrue(failed.knowledge().knowledgePersistenceBlocked());
            assertTrue(failed.resourceComplete());
            assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, failed.discoveryState());
            assertTrue(failed.readable().evidence().isEmpty());
            var first = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
            assertEquals(1, first.knowledge().size());
            assertEquals(DiscoveryState.READY, first.discoveryState());
            var repeated = DiscoveryCoordinator.discover(source, a.root(), first.knowledge(), o -> {
                throw new AssertionError("Unnecessary persistence");
            });
            assertSame(first.knowledge(), repeated.knowledge());
            assertEquals(DiscoveryState.READY, repeated.discoveryState());
            source.remove(a.id());
            var later = run(source, a.root(), failed.knowledge());
            assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, later.discoveryState()); // Sticky failure.
        }
    }

    @Test
    void oneFailedCommitAndCommitIoFailureDoNotInsertNewRecord() throws Exception {
        var a = fixture(TOKEN); var b = fixture(CHILD);
        var source = new DiscoveryFixtures(); source.put(a); source.put(b);
        for (boolean io : List.of(false, true)) {
            var result = DiscoveryCoordinator.discover(source, a.root(), DurableKnowledgeState.establishedEmpty(), o -> {
                if (o.record().objectId().equals(b.id())) {
                    if (io) { throw new IOException("external persistence unavailable"); }
                    return FAILED;
                }
                return COMMITTED;
            });
            assertEquals(1, result.knowledge().size());
            assertNotNull(result.readable().get(a.id()));
            assertNull(result.readable().get(b.id()));
            assertTrue(result.resourceComplete());
            assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        }
    }

    @Test
    void invalidBytesCanCoexistWithReadyAndCreateNoKnowledge() throws Exception {
        var a = fixture(TOKEN); var invalid = semantic(a.root(), new byte[0]);
        var source = new DiscoveryFixtures(); source.put(a); source.put(invalid);
        source.put(ObjectId.fromFilename("b".repeat(64)), new byte[1023]);
        source.put(ObjectId.fromFilename("c".repeat(64)), new byte[1024]);
        var result = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertEquals(1, result.knowledge().size());
        assertEquals(List.of(ObjectDiscovery.Classification.INVALID, ObjectDiscovery.Classification.INVALID_STORAGE,
                ObjectDiscovery.Classification.INVALID_STORAGE, ObjectDiscovery.Classification.SUPPORTED_VALID).stream()
                .sorted().toList(), result.observations().stream().map(ObjectDiscovery.Observation::classification).sorted().toList());
    }

    @Test
    void realAuthenticatedInvalidKnownIdAndValidMismatchEnterContinuityUnknown() throws Exception {
        var a = fixture(TOKEN); var invalid = semantic(a.root(), new byte[0]);
        var source = new DiscoveryFixtures(); source.put(a);
        var valid = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        var record = (KnownTokenNode) valid.knowledge().record(a.id());
        // Trusted corrupt-memory seam: no claim of manufacturing a keyed-ID collision.
        for (var object : List.of(invalid, a)) {
            var seed = new KnownTokenNode(object.id(), 1, SemanticStatus.SUPPORTED_VALID, record.tokenId(),
                    List.of(), record.authorDeviceId(), record.authorTime().add(BigInteger.ONE));
            var known = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(seed, COMMITTED).state();
            source.entries.clear(); source.put(object);
            var result = DiscoveryCoordinator.discover(source, a.root(), known, o -> {
                throw new AssertionError("Must not overwrite known contradiction");
            });
            assertEquals(seed, result.knowledge().record(object.id()));
            assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN, result.knowledge().continuity());
            assertTrue(result.resourceComplete());
            assertEquals(DiscoveryState.READY, result.discoveryState());
            assertFalse(new VaultReadiness(result.knowledge(), result.discoveryState()).baseOperationSafe());
            assertTrue(result.readable().evidence().isEmpty());
        }
    }

    @Test
    void assertionInvalidDeviceGoesThroughRealValidator() throws Exception {
        var vector = DurableKnowledgeTest.fixture("v1.crypto.device-root.001");
        var fields = TlvTestBytes.fields(vector.semanticBytes());
        var altered = new ArrayList<TlvField>();
        for (var field : fields) {
            byte[] value = field.value().clone();
            if (field.tag() == 0x0200) { value[0] ^= 1; }
            altered.add(new TlvField(field.tag(), value));
        }
        var a = semantic(vector.data().field("root_hex").hex(), TlvTestBytes.encode(altered));
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE,
                EnvelopeReader.open(a.id().filename(), a.bytes(), a.root()).status());
        assertEquals(ObjectDiscovery.Classification.INVALID, new ObjectDiscovery().classify(a.id(), a.bytes(), a.root()).classification());
    }

    @Test
    void knownStorageCorruptionNeverErasesKnowledgeOrLosesContinuity() throws Exception {
        var a = fixture(TOKEN); var source = new DiscoveryFixtures(); source.put(a);
        var known = run(source, a.root(), DurableKnowledgeState.establishedEmpty()).knowledge();
        var vector = DurableKnowledgeTest.fixture(TOKEN); var c = vector.data().field("crypto");
        byte[] padding = c.field("padded_plaintext_hex").hex(); padding[1007] = 1;
        byte[] identity = c.field("padded_plaintext_hex").hex(); identity[2] ^= 1;
        var bad = List.of(new byte[3], new byte[1024],
                CryptoVectorTest.encrypt(c.field("object_key_hex").hex(), c.field("nonce_hex").hex(), c.field("aad_hex").hex(), padding),
                CryptoVectorTest.encrypt(c.field("object_key_hex").hex(), c.field("nonce_hex").hex(), c.field("aad_hex").hex(), identity));
        var reasons = List.of(ObjectDiscovery.Detail.WRONG_LENGTH, ObjectDiscovery.Detail.AEAD,
                ObjectDiscovery.Detail.PADDING, ObjectDiscovery.Detail.OBJECT_ID);
        for (int i = 0; i < bad.size(); i++) {
            source.put(a.id(), bad.get(i));
            var result = run(source, a.root(), known);
            assertEquals(reasons.get(i), result.observations().get(0).detail());
            assertEquals(known.records(), result.knowledge().records());
            assertEquals(known.continuity(), result.knowledge().continuity());
            assertTrue(result.readable().evidence().isEmpty());
            assertTrue(result.resourceComplete());
        }
    }

    @Test
    void allEnumerationPermutationsHaveEquivalentResults() throws Exception {
        var objects = List.of(fixture(TOKEN), fixture(CHILD), fixture(FUTURE));
        var orders = new ArrayList<List<ObjectBytes>>();
        for (int i = 0; i < 3; i++) {
            var order = new ArrayList<>(objects); Collections.rotate(order, i); orders.add(List.copyOf(order));
            Collections.reverse(order); orders.add(List.copyOf(order));
        }
        DiscoveryResult previous = null;
        for (var order : orders) {
            var source = new DiscoveryFixtures(); order.forEach(source::put);
            var result = run(source, objects.get(0).root(), DurableKnowledgeState.establishedEmpty());
            if (previous != null) {
                assertEquals(previous.knowledge().records(), result.knowledge().records());
                assertEquals(previous.observations().stream().map(ObjectDiscovery.Observation::toString).toList(),
                        result.observations().stream().map(ObjectDiscovery.Observation::toString).toList());
                assertEquals(previous.discoveryState(), result.discoveryState());
                var token = result.readable().get(objects.get(0).id()).tokenId();
                assertEquals(previous.topology().currentTokenHeads(token), result.topology().currentTokenHeads(token));
            }
            previous = result;
        }
    }

    @Test
    void snapshotCollectionsAreImmutableAndBindingsCannotBeMixed() throws Exception {
        var a = fixture(TOKEN); var source = new DiscoveryFixtures(); source.put(a);
        var snapshot = source.snapshot();
        assertThrows(UnsupportedOperationException.class, () -> snapshot.candidates().clear());
        var result = run(source, a.root(), DurableKnowledgeState.establishedEmpty());
        assertThrows(UnsupportedOperationException.class, () -> result.observations().clear());
        assertThrows(IllegalStateException.class, () -> new DiscoveryResult(result.observations(), result.snapshotIssue(),
                true, result.discoveryState(), result.knowledge(), new GraphTopology(result.knowledge()), result.readable()));
        assertFalse(result.toString().contains("SECRET"));
    }

    static TokenOperationPolicy policy(DiscoveryResult result, SecurityBytes token) {
        return new TokenOperationPolicy(new VaultReadiness(result.knowledge(), result.discoveryState()),
                result.topology(), token, result.readable());
    }

    static final class CountingChannel implements ReadableByteChannel {
        final int length; final int chunk;
        int consumed; int calls; boolean sawEof; boolean open = true;
        CountingChannel(int length, int chunk) { this.length = length; this.chunk = chunk; }
        @Override public int read(ByteBuffer target) {
            calls++;
            if (consumed == length) { sawEof = true; return -1; }
            int n = Math.min(Math.min(chunk, target.remaining()), length - consumed);
            for (int i = 0; i < n; i++) { target.put((byte) 0); }
            consumed += n; return n;
        }
        @Override public boolean isOpen() { return open; }
        @Override public void close() { open = false; }
    }
}
