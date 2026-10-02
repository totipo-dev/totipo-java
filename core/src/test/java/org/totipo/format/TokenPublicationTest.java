package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static org.totipo.format.V1ObjectPublicationStore.PublicationResult.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenPublicationTest {
    static byte[] root() { byte[] root = new byte[32]; Arrays.fill(root, (byte) 17); return root; }
    static TokenValue value(int status, String account) {
        return new TokenValue(status, "Issuer", account,
                new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[]{1, 2, 3}, 3)));
    }
    static TokenMetadata metadata() { return new TokenMetadata(Optional.of(""), Optional.of(new UInt64(-1))); }
    static TokenId tokenId() { return new TokenId(new byte[32]); }
    static List<ObjectId> parents(int count) {
        var parents = new ArrayList<ObjectId>();
        for (int i = 0; i < count; i++) { byte[] id = new byte[32]; id[31] = (byte)(i + 1); parents.add(new ObjectId(id)); }
        return parents;
    }
    static TokenPublicationPlan plan(int width) {
        return TokenPublicationPlan.planAssertion(tokenId(), parents(width), value(1, "chosen"), metadata(), root());
    }

    @Test void newIdIsOneDefensivelyCopied32ByteDrawAndBufferIsWiped() {
        byte[][] borrowed = new byte[1][];
        int[] calls = {0};
        EntropySource entropy = bytes -> { calls[0]++; assertEquals(32, bytes.length); borrowed[0] = bytes; Arrays.fill(bytes, (byte) 42); };
        byte[] root = root();
        var value = value(2, "new tombstone");
        var plan = TokenPublicationPlan.planNew(value, metadata(), entropy, root);
        assertEquals(1, calls[0]);
        assertArrayEquals(new byte[32], borrowed[0]);
        assertEquals(1, plan.stages().size());
        var token = plan.stages().get(0).token();
        byte[] id = new byte[32]; Arrays.fill(id, (byte)42);
        assertArrayEquals(id, token.tokenId().bytes());
        assertEquals(List.of(), token.parents());
        assertEquals(value, token.value()); assertEquals(metadata(), token.metadata());
        assertArrayEquals(root(), root);
        Arrays.fill(root, (byte) 0);
        assertEquals(plan.stages(), TokenPublicationPlan.planAssertion(token.tokenId(), List.of(), value, metadata(), root()).stages());
        assertEquals(List.of(List.class), Arrays.stream(TokenPublicationPlan.class.getDeclaredFields()).map(java.lang.reflect.Field::getType).toList());
        assertThrows(UnsupportedOperationException.class, () -> plan.stages().clear());
    }

    @Test void entropyFailureStillWipesAndProductionDefaultWorks() {
        byte[][] borrowed = new byte[1][];
        assertThrows(IllegalStateException.class, () -> TokenPublicationPlan.planNew(value(1, "new"), metadata(), bytes -> {
            borrowed[0] = bytes; Arrays.fill(bytes, (byte) 77); throw new IllegalStateException("Entropy unavailable");
        }, root()));
        assertArrayEquals(new byte[32], borrowed[0]);
        assertEquals(32, TokenPublicationPlan.planNew(value(1, "new"), metadata(), root())
                .stages().get(0).token().tokenId().bytes().length);
    }

    @ParameterizedTest @ValueSource(ints = {0, 1, 4, 5, 11})
    void explicitUnavailableParentsFoldDeterministically(int width) {
        var supplied = parents(width);
        var plan = plan(width);
        assertEquals(width <= 4 ? 1 : (width + 1) / 3, plan.stages().size());
        Collections.reverse(supplied);
        var retry = TokenPublicationPlan.planAssertion(tokenId(), supplied, value(1, "chosen"), metadata(), root());
        assertEquals(plan.stages(), retry.stages());
        var remaining = parents(width).iterator();
        ObjectId carry = null;
        for (var stage : plan.stages()) {
            var expectedParents = new ArrayList<ObjectId>();
            int take = carry == null ? 4 : 3;
            if (carry != null) expectedParents.add(carry);
            for (int i = 0; i < take && remaining.hasNext(); i++) expectedParents.add(remaining.next());
            expectedParents.sort(TokenGraph.OBJECT_ORDER);
            assertEquals(expectedParents, stage.token().parents());
            assertEquals(tokenId(), stage.token().tokenId());
            assertEquals(value(1, "chosen"), stage.token().value());
            assertEquals(metadata(), stage.token().metadata());
            byte[] semantic = TokenWriter.write(stage.token());
            try { assertEquals(stage.objectId(), V1EnvelopeWriter.seal(root(), semantic).id()); }
            finally { Arrays.fill(semantic, (byte) 0); }
            carry = stage.objectId();
        }
        assertFalse(remaining.hasNext());
    }

    @Test void duplicateParentsRejectedBeforeFold() {
        var id = parents(1).get(0);
        assertThrows(IllegalArgumentException.class, () -> TokenPublicationPlan.planAssertion(tokenId(),
                List.of(id, id), value(1, "chosen"), metadata(), root()));
    }

    @Test void liveTombstoneRestoreAndAbsentZeroMaxMetadataUseSameMechanics() {
        for (var metadata : List.of(new TokenMetadata(Optional.empty(), Optional.empty()),
                new TokenMetadata(Optional.of("name"), Optional.of(new UInt64(0))), metadata())) {
            for (int status : List.of(1, 2, 1)) {
                var plan = TokenPublicationPlan.planAssertion(tokenId(), parents(11), value(status, "value"), metadata, root());
                for (var stage : plan.stages()) {
                    assertEquals(status, stage.token().value().status());
                    assertEquals(metadata, stage.token().metadata());
                }
            }
        }
    }

    @Test void allNewAllExactAndMixedAcknowledgements() throws Exception {
        var plan = plan(11);
        var store = new PublicationTestStore();
        assertEquals(Collections.nCopies(4, PUBLISHED_NEW), TokenPublisher.publish(plan, root(), store));
        assertEquals(Collections.nCopies(4, ALREADY_PRESENT_EXACT), TokenPublisher.publish(plan, root(), store));
        assertEquals(4, store.objects.size());
        store.objects.remove(plan.stages().get(0).objectId());
        assertEquals(List.of(PUBLISHED_NEW, ALREADY_PRESENT_EXACT, ALREADY_PRESENT_EXACT, ALREADY_PRESENT_EXACT),
                TokenPublisher.publish(plan, root(), store));
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void partialFailureStopsAndExplicitSamePlanRetryIsSafe(boolean residue) throws Exception {
        var plan = plan(11);
        var store = new PublicationTestStore(); store.failCall = 3; store.installOnFailure = residue;
        assertThrows(IOException.class, () -> TokenPublisher.publish(plan, root(), store));
        assertEquals(3, store.calls);
        assertEquals(2 + (residue ? 1 : 0), store.objects.size());
        assertFalse(store.objects.containsKey(plan.stages().get(3).objectId()));
        var prior = new java.util.HashMap<>(store.objects);
        var observed = store.objects.entrySet().stream().map(e -> new DiscoverySource.Candidate(e.getKey(),
                () -> java.nio.channels.Channels.newChannel(new java.io.ByteArrayInputStream(e.getValue())))).toList();
        assertEquals(store.objects.size(), TokenStoreReader.read(() -> new DiscoverySource.Snapshot(observed,
                DiscoverySource.SnapshotIssue.NONE), root()).validatedTokens().size());
        store.failCall = -1;
        assertEquals(List.of(ALREADY_PRESENT_EXACT, ALREADY_PRESENT_EXACT,
                residue ? ALREADY_PRESENT_EXACT : PUBLISHED_NEW, PUBLISHED_NEW), TokenPublisher.publish(plan, root(), store));
        prior.forEach((id, bytes) -> assertArrayEquals(bytes, store.objects.get(id)));
        assertEquals(plan.stages(), plan(11).stages());
    }

    @Test void collisionAndWrongRootFailWithoutLaterPublications() {
        var plan = plan(11);
        var store = new PublicationTestStore();
        byte[] collision = new byte[1024];
        store.objects.put(plan.stages().get(0).objectId(), collision.clone());
        assertThrows(IOException.class, () -> TokenPublisher.publish(plan, root(), store));
        assertEquals(1, store.calls); assertEquals(1, store.objects.size());
        assertArrayEquals(collision, store.objects.get(plan.stages().get(0).objectId()));
        var empty = new PublicationTestStore();
        assertThrows(IllegalArgumentException.class, () -> TokenPublisher.publish(plan, new byte[32], empty));
        assertEquals(0, empty.calls);
        assertEquals(value(1, "chosen"), plan.stages().get(0).token().value());
    }

    @Test void missingAcknowledgementDoesNotSucceed() {
        var store = new V1ObjectPublicationStore() {
            @Override public PublicationResult publish(ObjectId id, byte[] bytes) { return null; }
            @Override public void close() {}
        };
        assertThrows(IOException.class, () -> TokenPublisher.publish(plan(0), root(), store));
    }
}
