package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.TokenGraphTest.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenFoldTest {
    @Test void zeroThroughFourParentsProduceOneOrdinaryAssertion() {
        for (int width = 0; width <= 4; width++) {
            var parents = parents(width);
            var stages = TokenFold.build(T, parents, X, ABSENT, new byte[32]);
            assertEquals(1, stages.size());
            assertEquals(parents, stages.get(0).token().parents());
            assertEquals(X, stages.get(0).token().value());
        }
    }

    @Test void fixedCarryWidthsAndRealIntermediateIdentities() {
        for (int width : new int[]{5, 7, 10, 11, 101}) {
            var original = parents(width);
            var stages = TokenFold.build(T, original, X, ABSENT, new byte[32]);
            assertEquals((width + 1) / 3, stages.size());
            int offset = 0;
            ObjectId previous = null;
            for (var stage : stages) {
                var expected = new ArrayList<ObjectId>();
                if (previous != null) expected.add(previous);
                int count = previous == null ? 4 : Math.min(3, width - offset);
                expected.addAll(original.subList(offset, offset + count));
                offset += count;
                expected.sort((a, b) -> Arrays.compareUnsigned(a.bytes(), b.bytes()));
                assertEquals(expected, stage.token().parents());
                assertEquals(stage.objectId(), V1EnvelopeWriter.seal(new byte[32], TokenWriter.write(stage.token())).id());
                previous = stage.objectId();
            }
            assertEquals(width, offset);
        }
    }

    @Test void originalOrderingIsUnsignedAndIndependentOfInputPermutationAndDuplicates() {
        var input = new ArrayList<>(List.of(id(-1), id(0), id(Integer.MIN_VALUE), id(Integer.MAX_VALUE), id(1), id(2), id(3)));
        var expected = TokenFold.build(T, input, X, ABSENT, new byte[32]);
        assertEquals(List.of(id(0), id(1), id(2), id(3)), expected.get(0).token().parents());
        for (int i = 0; i < input.size(); i++) {
            Collections.rotate(input, 1);
            assertEquals(expected, TokenFold.build(T, input, X, ABSENT, new byte[32]));
        }
        Collections.reverse(input);
        input.add(id(0));
        assertEquals(expected, TokenFold.build(T, input, X, ABSENT, new byte[32]));
    }

    @Test void metadataPresenceAndUnsignedTimeBoundariesAreExactAcrossEveryStage() {
        for (var metadata : List.of(ABSENT,
                new TokenMetadata(Optional.of(""), Optional.of(new UInt64(0))),
                new TokenMetadata(Optional.of(" e\u0301 Laptop 😀\u0000 "), Optional.empty()),
                new TokenMetadata(Optional.empty(), Optional.of(new UInt64(-1))))) {
            var stages = TokenFold.build(T, parents(11), X, metadata, new byte[32]);
            var ids = new HashSet<ObjectId>();
            var parentLists = new HashSet<List<ObjectId>>();
            for (var stage : stages) {
                assertSame(X, stage.token().value());
                assertSame(metadata, stage.token().metadata());
                assertEquals(T, stage.token().tokenId());
                assertEquals(stage.token(), TokenReader.read(TokenWriter.write(stage.token())));
                assertTrue(ids.add(stage.objectId()));
                assertTrue(parentLists.add(stage.token().parents()));
            }
            assertEquals(4, stages.size());
        }
    }

    @Test void maximumFieldLengthsDoNotChangeFoldGroupingOrWidth() {
        var maximum = new TokenValue(2, "i".repeat(256), "a".repeat(256),
                new TokenValue.Credential(3, 8, 0xffff_ffffL, new SecurityBytes(new byte[128], 128)));
        var metadata = new TokenMetadata(Optional.of("c".repeat(128)), Optional.of(new UInt64(-1)));
        var shortStages = TokenFold.build(T, parents(11), X, ABSENT, new byte[32]);
        var longStages = TokenFold.build(T, parents(11), maximum, metadata, new byte[32]);
        assertEquals(shortStages.size(), longStages.size());
        for (int i = 0; i < longStages.size(); i++) {
            var large = longStages.get(i).token();
            assertEquals(shortStages.get(i).token().parents().size(), large.parents().size());
            var originalParents = new HashSet<>(large.parents());
            var shortParents = new HashSet<>(shortStages.get(i).token().parents());
            if (i > 0) {
                originalParents.remove(longStages.get(i - 1).objectId());
                shortParents.remove(shortStages.get(i - 1).objectId());
            }
            assertEquals(shortParents, originalParents);
            assertTrue(large.parents().size() <= 4);
            assertEquals(maximum, large.value());
            assertEquals(metadata, large.metadata());
            assertEquals(i < 3 ? 1005 : 933, TokenWriter.write(large).length);
        }
    }

    @Test void realFiveHeadFrontierIsIncorporatedByOrdinaryGraphEdges() { integrate(5); }
    @Test void realElevenHeadFrontierIsIncorporatedByOrdinaryGraphEdges() { integrate(11); }

    private static void integrate(int width) {
        byte[] root = new byte[32];
        Arrays.fill(root, (byte) 0xa5);
        var originals = new ArrayList<ValidatedToken>();
        for (int i = 0; i < width; i++) {
            // Real canonical plaintext and keyed identity for each distinct original object.
            var token = new TokenObject(T, List.of(), GraphFoldVectorChecks.value("original-" + i),
                    new TokenMetadata(Optional.of("device-" + i), Optional.of(new UInt64(-1L - i))));
            var sealed = V1EnvelopeWriter.seal(root, TokenWriter.write(token));
            var opened = EnvelopeReader.open(sealed.id().filename(), sealed.bytes(), root);
            originals.add(new ValidatedToken(opened.objectId(), TokenReader.read(opened.semanticBytes())));
        }
        assertEquals(width, TokenGraph.evaluate(originals).perToken(T).heads().size());
        assertEquals(TokenGraph.CurrentValueState.CONFLICT, TokenGraph.evaluate(originals).perToken(T).state());
        var metadata = new TokenMetadata(Optional.of("e\u0301 Phone 😀"), Optional.of(new UInt64(0)));
        var stages = TokenFold.build(T, originals.stream().map(ValidatedToken::objectId).toList(), X, metadata, root);
        var all = new ArrayList<>(originals);
        for (var stage : stages) {
            assertSame(metadata, stage.token().metadata());
            assertSame(X, stage.token().value());
            assertTrue(stage.token().parents().size() <= 4);
            var sealed = V1EnvelopeWriter.seal(root, TokenWriter.write(stage.token()));
            assertEquals(stage.objectId(), sealed.id());
            all.add(new ValidatedToken(stage.objectId(), stage.token()));
        }
        var last = stages.get(stages.size() - 1);
        var view = TokenGraph.evaluate(all).perToken(T);
        assertEquals(List.of(new ValidatedToken(last.objectId(), last.token())), view.heads());
        assertEquals(1, view.currentGroups().size());
        assertEquals(width + stages.size(), view.objects().size());
        assertEquals(Set.of(X), view.currentValues());
        assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, view.state());
        assertTrue(view.unresolvedParents().isEmpty());
    }

    @Test void foldResultsOwnCollectionsAndBorrowRootWithoutChangingIt() {
        var input = new ArrayList<>(parents(5));
        byte[] root = new byte[32];
        Arrays.fill(root, (byte) 0x97);
        byte[] originalRoot = root.clone();
        var result = TokenFold.build(T, input, X, ABSENT, root);
        assertArrayEquals(originalRoot, root);
        input.clear();
        Arrays.fill(root, (byte) 0);
        assertEquals(result, TokenFold.build(T, parents(5), X, ABSENT, originalRoot));
        assertEquals(1, TokenFold.build(T, input, X, ABSENT, root).size());
        assertThrows(UnsupportedOperationException.class, () -> result.clear());
        assertThrows(UnsupportedOperationException.class, () -> result.get(0).token().parents().clear());
        assertEquals(X, result.get(0).token().value());
        assertSame(ABSENT, result.get(0).token().metadata());
        assertThrows(IllegalArgumentException.class, () -> TokenFold.build(T, input, X, ABSENT, new byte[31]));
    }

    private static List<ObjectId> parents(int count) {
        var ids = new ArrayList<ObjectId>();
        for (int i = 0; i < count; i++) ids.add(id(i));
        return ids;
    }
}
