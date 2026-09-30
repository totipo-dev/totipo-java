package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenStoreReaderTest {
    static final class TrackingChannel implements ReadableByteChannel {
        final byte[] bytes;
        int position;
        int maxRead;
        boolean closed, failRead, failClose;
        TrackingChannel(byte[] bytes) { this.bytes = bytes; }
        @Override public int read(ByteBuffer destination) throws IOException {
            if (failRead) throw new IOException("Injected read error");
            if (position == bytes.length) return -1;
            int count = Math.min(destination.remaining(), bytes.length - position);
            destination.put(bytes, position, count); position += count; maxRead += count; return count;
        }
        @Override public boolean isOpen() { return !closed; }
        @Override public void close() throws IOException { closed = true; if (failClose) throw new IOException("Injected close error"); }
    }
    static V1EnvelopeWriter.ObjectBytes object() {
        return V1EnvelopeWriter.seal(TokenPublicationTest.root(), TokenWriter.write(TokenPublicationTest.plan(1).stages().get(0).token()));
    }

    @ParameterizedTest @ValueSource(ints = {0, 1023, 1024, 1025, 100000})
    void exactBoundedReadingAndClose(int size) {
        var object = object();
        byte[] bytes = size == 1024 ? object.bytes() : Arrays.copyOf(object.bytes(), size);
        var channel = new TrackingChannel(bytes);
        var observation = TokenStoreReader.read(() -> new DiscoverySource.Snapshot(List.of(
                new DiscoverySource.Candidate(object.id(), () -> channel)), DiscoverySource.SnapshotIssue.NONE), TokenPublicationTest.root());
        assertTrue(channel.closed); assertEquals(Math.min(size, 1025), channel.maxRead);
        assertEquals(size == 1024 ? 1 : 0, observation.validatedTokens().size());
        assertEquals(size == 1024 ? List.of() : List.of(new TokenStoreObservation.CandidateDiagnostic(object.id(),
                TokenStoreObservation.Reason.INVALID_STORAGE)), observation.candidateDiagnostics());
    }

    @ParameterizedTest @ValueSource(strings = {"open", "read", "close"})
    void unavailableCandidateAndSnapshotCloseDoNotDiscardIndependentValidObjects(String mode) throws Exception {
        var object = object();
        var failed = new TrackingChannel(object.bytes());
        failed.failRead = mode.equals("read"); failed.failClose = mode.equals("close");
        var good = new TrackingChannel(object.bytes());
        var badId = new ObjectId(new byte[32]);
        int[] snapshotCloses = {0};
        var observation = TokenStoreReader.read(() -> new DiscoverySource.Snapshot(List.of(
                new DiscoverySource.Candidate(badId, () -> {
                    if (mode.equals("open")) throw new IOException("Injected open failure");
                    return failed;
                }), new DiscoverySource.Candidate(object.id(), () -> good)), DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE,
                () -> { snapshotCloses[0]++; throw new IOException("Injected snapshot close failure"); }), TokenPublicationTest.root());
        assertTrue(good.closed); if (!mode.equals("open")) assertTrue(failed.closed);
        assertEquals(1, snapshotCloses[0]);
        assertEquals(1, observation.validatedTokens().size());
        assertTrue(observation.candidateDiagnostics().contains(new TokenStoreObservation.CandidateDiagnostic(badId,
                TokenStoreObservation.Reason.UNAVAILABLE)));
        assertFalse(observation.snapshotDiagnostics().isEmpty());
        assertEquals(1, TokenGraph.evaluate(observation.validatedTokens()).perToken().size());
        // Descriptive diagnostics do not participate in either authoring factory or publisher.
        assertEquals(1, TokenPublisher.publish(TokenPublicationTest.plan(1), TokenPublicationTest.root(), new PublicationTestStore()).size());
        assertThrows(UnsupportedOperationException.class, () -> observation.validatedTokens().clear());
        assertThrows(UnsupportedOperationException.class, () -> observation.candidateDiagnostics().clear());
        assertThrows(UnsupportedOperationException.class, () -> observation.snapshotDiagnostics().clear());
    }

    @Test void closeFailureAfterValidationRetainsTheValidToken() {
        var object = object(); var channel = new TrackingChannel(object.bytes()); channel.failClose = true;
        var result = TokenStoreReader.read(() -> new DiscoverySource.Snapshot(List.of(
                new DiscoverySource.Candidate(object.id(), () -> channel)), DiscoverySource.SnapshotIssue.NONE), TokenPublicationTest.root());
        assertEquals(1, result.validatedTokens().size());
        assertEquals(TokenStoreObservation.Reason.UNAVAILABLE, result.candidateDiagnostics().get(0).reason());
    }

    @Test void namespaceFailureAndNonprogressAreDiagnostics() {
        var result = TokenStoreReader.read(() -> { throw new IOException("Sensitive provider details"); }, TokenPublicationTest.root());
        assertEquals(List.of(DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE), result.snapshotDiagnostics());
        assertFalse(result.toString().contains("Sensitive"));
        var object = object();
        var channel = new ReadableByteChannel() {
            boolean open = true;
            @Override public int read(ByteBuffer bytes) { return 0; }
            @Override public boolean isOpen() { return open; }
            @Override public void close() { open = false; }
        };
        var stalled = TokenStoreReader.read(() -> new DiscoverySource.Snapshot(List.of(new DiscoverySource.Candidate(object.id(), () -> channel)),
                DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE), TokenPublicationTest.root());
        assertFalse(channel.isOpen());
        assertEquals(List.of(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE), stalled.snapshotDiagnostics());
        assertEquals(TokenStoreObservation.Reason.UNAVAILABLE, stalled.candidateDiagnostics().get(0).reason());
    }

    @Test void envelopeFailuresAndAuthenticatedGrammarFailureRemainDistinct() throws Exception {
        for (var vector : dev.totipo.conformance.VectorCaseLoader.cryptoCases()) {
            if (vector.expected().equals("SUPPORTED_VALID")) continue;
            var crypto = vector.data().field("post_aead");
            ObjectId id = ObjectId.fromFilename(crypto.field("object_id").string());
            var channel = new TrackingChannel(crypto.field("object_hex").hex());
            var observation = TokenStoreReader.read(() -> new DiscoverySource.Snapshot(List.of(
                    new DiscoverySource.Candidate(id, () -> channel)), DiscoverySource.SnapshotIssue.NONE), vector.data().field("root_hex").hex());
            assertEquals(List.of(), observation.validatedTokens());
            assertEquals(TokenStoreObservation.Reason.INVALID_STORAGE, observation.candidateDiagnostics().get(0).reason());
        }
        var malformed = V1EnvelopeWriter.seal(TokenPublicationTest.root(), new byte[]{0});
        var channel = new TrackingChannel(malformed.bytes());
        var observation = TokenStoreReader.read(() -> new DiscoverySource.Snapshot(List.of(
                new DiscoverySource.Candidate(malformed.id(), () -> channel)), DiscoverySource.SnapshotIssue.NONE), TokenPublicationTest.root());
        assertEquals(List.of(), observation.validatedTokens());
        assertEquals(TokenStoreObservation.Reason.INVALID_TOKEN, observation.candidateDiagnostics().get(0).reason());
    }

    @Test void readerWipesEnvelopeResultWithoutChangingCallerRootOrToken() {
        byte[] root = TokenPublicationTest.root();
        var object = object();
        var result = EnvelopeReader.open(object.id().filename(), object.bytes(), root);
        byte[] copy = result.semanticBytes();
        result.clear();
        assertArrayEquals(new byte[copy.length], result.semanticBytes());
        assertEquals(TokenPublicationTest.plan(1).stages().get(0).token(), TokenReader.read(copy));
        Arrays.fill(copy, (byte) 0);
        assertArrayEquals(TokenPublicationTest.root(), root);
    }
}
