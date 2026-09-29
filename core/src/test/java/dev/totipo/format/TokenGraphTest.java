package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenGraphTest {
    static final TokenId T = new TokenId(new byte[32]);
    static final TokenMetadata ABSENT = new TokenMetadata(Optional.empty(), Optional.empty());
    static final TokenValue X = GraphFoldVectorChecks.value("X");
    static final TokenValue Y = GraphFoldVectorChecks.value("Y");

    static ObjectId id(int number) { return new ObjectId(ByteBuffer.allocate(32).putInt(number).array()); }

    static ValidatedToken node(int number, int... parents) { return node(number, T, X, ABSENT, parents); }

    static ValidatedToken node(int number, TokenId identity, TokenValue value, TokenMetadata metadata, int... parents) {
        var ids = new ArrayList<ObjectId>();
        for (int parent : parents) ids.add(id(parent));
        ids.sort(TokenGraph.OBJECT_ORDER);
        return new ValidatedToken(id(number), new TokenObject(identity, ids, value, metadata));
    }

    static TokenGraph.View view(ValidatedToken... nodes) { return TokenGraph.evaluate(List.of(nodes)).perToken(T); }

    @Test void emptyGraph() {
        var result = TokenGraph.evaluate(List.of());
        assertTrue(result.perToken().isEmpty());
        assertTrue(result.contradictoryObjectIds().isEmpty());
        assertEquals(TokenGraph.CurrentValueState.EMPTY, result.perToken(T).state());
        assertTrue(result.perToken(T).heads().isEmpty());
    }

    @Test void singleObject() {
        var a = node(1);
        assertEquals(List.of(a), view(a).objects());
        assertEquals(List.of(List.of(a)), view(a).currentGroups());
        assertEquals(List.of(a), view(a).heads());
        assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, view(a).state());
    }

    @Test void childNotRootIsCurrentOrientationRegression() {
        var a = node(1);
        var b = node(2, 1);
        assertEquals(List.of(b), view(a, b).heads());
        assertEquals(List.of(List.of(b)), view(a, b).currentGroups());
    }

    @Test void concurrentRootsRetainBothEqualValuedObjects() {
        var a = node(1);
        var b = node(2);
        assertEquals(List.of(a, b), view(a, b).heads());
        assertEquals(List.of(List.of(a), List.of(b)), view(a, b).currentGroups());
        assertEquals(Set.of(X), view(a, b).currentValues());
        assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, view(a, b).state());
    }

    @Test void mergeSupersedesBothBranches() {
        var merge = node(3, 1, 2);
        assertEquals(List.of(merge), view(node(1), node(2), merge).heads());
    }

    @Test void missingParentDoesNotHideCompleteValue() {
        var child = node(2, 1);
        var view = view(child);
        assertEquals(List.of(child), view.heads());
        assertEquals(Set.of(X), view.currentValues());
        assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, view.state());
        assertEquals(List.of(new TokenGraph.UnresolvedParent(id(2), id(1))), view.unresolvedParents());
    }

    @Test void wrongIdentityParentIsUnresolvedAndIndependentlyCurrent() {
        var u = new TokenId(id(99).bytes());
        var a = node(1, u, X, ABSENT);
        var b = node(2, 1);
        var graph = TokenGraph.evaluate(List.of(a, b));
        assertEquals(List.of(a), graph.perToken(u).heads());
        assertEquals(List.of(b), graph.perToken(T).heads());
        assertEquals(List.of(new TokenGraph.UnresolvedParent(id(2), id(1))), graph.perToken(T).unresolvedParents());
    }

    @Test void allSevenValueFieldsIndependentlyCreateConflict() {
        var c = X.credential();
        var differences = List.of(new TokenValue(2, X.issuer(), X.account(), c),
                new TokenValue(1, "other", X.account(), c), new TokenValue(1, X.issuer(), "other", c),
                new TokenValue(1, X.issuer(), X.account(), new TokenValue.Credential(2, 6, 30, c.secret())),
                new TokenValue(1, X.issuer(), X.account(), new TokenValue.Credential(1, 7, 30, c.secret())),
                new TokenValue(1, X.issuer(), X.account(), new TokenValue.Credential(1, 6, 31, c.secret())),
                new TokenValue(1, X.issuer(), X.account(), new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[]{43}, 1))));
        for (var different : differences) {
            var b = node(2, T, different, ABSENT);
            assertEquals(TokenGraph.CurrentValueState.CONFLICT, view(node(1), b).state());
            assertEquals(Set.of(X, different), view(node(1), b).currentValues());
            assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, view(b).state()); // Includes tombstone.
        }
    }

    @Test void metadataNeverChangesTopologyOrValueAndEveryHeadRetainsItsOwn() {
        var variants = List.of(ABSENT, new TokenMetadata(Optional.of(""), Optional.empty()),
                new TokenMetadata(Optional.empty(), Optional.of(new UInt64(0))),
                new TokenMetadata(Optional.of("Laptop"), Optional.of(new UInt64(1))),
                new TokenMetadata(Optional.of("Phone"), Optional.of(new UInt64(-1))));
        for (var metadata : variants) {
            var a = node(1);
            var b = node(2, T, X, metadata);
            var concurrent = view(a, b);
            assertEquals(List.of(a, b), concurrent.heads());
            assertSame(metadata, concurrent.heads().get(1).token().metadata());
            assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, concurrent.state());
            assertEquals(Set.of(X), concurrent.currentValues());
            var cycleA = node(1, 2);
            var cycleB = node(2, T, X, metadata, 1);
            assertEquals(List.of(List.of(cycleA, cycleB)), view(cycleA, cycleB).currentGroups());
            assertEquals(Set.of(X), view(cycleA, cycleB).currentValues());
            assertEquals(List.of(cycleB), view(a, cycleB).heads());
            assertTrue(view(a, cycleB).unresolvedParents().isEmpty());
        }
    }

    @Test void selfCycleIsAnOrdinarySingletonGroup() {
        var a = node(1, 1);
        assertEquals(List.of(List.of(a)), view(a).currentGroups());
        assertTrue(view(a).unresolvedParents().isEmpty());
    }

    @Test void twoNodeCyclePreservesBothHeadsAndTheirConflictingValues() {
        var a = node(1, 2);
        var b = node(2, T, Y, ABSENT, 1);
        assertEquals(List.of(List.of(a, b)), view(a, b).currentGroups());
        assertEquals(List.of(a, b), view(a, b).heads());
        assertEquals(TokenGraph.CurrentValueState.CONFLICT, view(a, b).state());
    }

    @Test void threeNodeCycle() {
        var a = node(1, 2);
        var b = node(2, 3);
        var c = node(3, 1);
        assertEquals(List.of(List.of(a, b, c)), view(a, b, c).currentGroups());
    }

    @Test void descendantOfOneMemberSupersedesEntireScc() {
        var descendant = node(3, 1);
        assertEquals(List.of(descendant), view(node(1, 2), node(2, 1), descendant).heads());
    }

    @Test void independentCurrentSccsKeepAllMembers() {
        var a = node(1, 2);
        var b = node(2, 1);
        var c = node(3, 4);
        var d = node(4, 3);
        assertEquals(List.of(List.of(a, b), List.of(c, d)), view(a, b, c, d).currentGroups());
        assertEquals(List.of(a, b, c, d), view(a, b, c, d).heads());
    }

    @Test void exactDuplicateCollapsesObjectHeadAndParentClaim() {
        var a = node(1, 99);
        var copy = node(1, 99);
        assertNotSame(a, copy);
        assertEquals(List.of(a), view(a, copy, a).objects());
        assertEquals(List.of(a), view(a, copy, a).heads());
        assertEquals(List.of(new TokenGraph.UnresolvedParent(id(1), id(99))), view(a, copy, a).unresolvedParents());
    }

    @Test void contradictoryIdentityIsExcludedEvenAfterAnotherMatchingDuplicate() {
        var a = node(1);
        var different = node(1, T, Y, ABSENT);
        var result = TokenGraph.evaluate(List.of(a, different, a));
        assertEquals(Set.of(id(1)), result.contradictoryObjectIds());
        assertEquals(TokenGraph.CurrentValueState.EMPTY, result.perToken(T).state());
        assertTrue(result.perToken(T).objects().isEmpty());
        for (var other : List.of(node(1, 2), node(1, T, X, new TokenMetadata(Optional.of(""), Optional.empty())),
                node(1, new TokenId(id(99).bytes()), X, ABSENT))) {
            assertEquals(Set.of(id(1)), TokenGraph.evaluate(List.of(a, other)).contradictoryObjectIds());
        }
    }

    @Test void contradictionReferencedByChildAndUnrelatedTokenIsolation() {
        var u = new TokenId(id(99).bytes());
        var other = node(4, u, X, ABSENT);
        var child = node(2, 1);
        var result = TokenGraph.evaluate(List.of(node(1), node(1, T, Y, ABSENT), child, other));
        assertEquals(List.of(child), result.perToken(T).heads());
        assertEquals(List.of(new TokenGraph.UnresolvedParent(id(2), id(1))), result.perToken(T).unresolvedParents());
        assertEquals(List.of(other), result.perToken(u).heads());
        // A later supplied snapshot has no memory of the contradiction.
        assertTrue(TokenGraph.evaluate(List.of(node(1), child)).contradictoryObjectIds().isEmpty());
        assertTrue(view(node(1), child).unresolvedParents().isEmpty());
    }

    @Test void disappearingIntermediateDoesNotCreateAnAncestralShortcut() {
        var a = node(1);
        var b = node(2, 1);
        var c = node(3, 2);
        assertEquals(List.of(c), view(a, b, c).heads());
        assertEquals(List.of(a, c), view(a, c).heads());
        assertEquals(List.of(new TokenGraph.UnresolvedParent(id(3), id(2))), view(a, c).unresolvedParents());
        assertEquals(List.of(c), view(a, b, c).heads());
    }

    @Test void lateCycleIsFreshRecomputation() {
        var a = node(1, 2);
        var b = node(2, 3);
        var c = node(3, 1);
        var before = view(a, b);
        assertEquals(List.of(a), before.heads());
        assertEquals(List.of(List.of(a, b, c)), view(a, b, c).currentGroups());
        assertEquals(before, view(a, b));
    }

    @Test void permutationsOfChainsForksMergesCyclesMultipleSccsAndContradictions() {
        for (var graph : List.of(List.of(node(1), node(2, 1), node(3, 2)),
                List.of(node(1), node(2, 1), node(3, 1)),
                List.of(node(1), node(2, 1), node(3, 1), node(4, 2, 3)),
                List.of(node(1, 2), node(2, 3), node(3, 1)),
                List.of(node(1, 2), node(2, 1), node(3, 4), node(4, 3), node(5, 1)),
                List.of(node(1), node(1, T, Y, ABSENT), node(1), node(2, 1)),
                List.of(node(1), node(2, new TokenId(id(99).bytes()), Y, ABSENT)))) {
            permutations(new ArrayList<>(graph), 0, TokenGraph.evaluate(graph));
        }
    }

    private static void permutations(ArrayList<ValidatedToken> graph, int offset, TokenGraph.Result expected) {
        if (offset == graph.size()) {
            var actual = TokenGraph.evaluate(graph);
            assertEquals(expected, actual);
            assertEquals(new ArrayList<>(expected.perToken().keySet()), new ArrayList<>(actual.perToken().keySet()));
            assertEquals(new ArrayList<>(expected.contradictoryObjectIds()), new ArrayList<>(actual.contradictoryObjectIds()));
            for (var id : expected.perToken().keySet()) {
                assertEquals(new ArrayList<>(expected.perToken(id).currentValues()), new ArrayList<>(actual.perToken(id).currentValues()));
            }
            return;
        }
        for (int i = offset; i < graph.size(); i++) {
            Collections.swap(graph, offset, i);
            permutations(graph, offset + 1, expected);
            Collections.swap(graph, offset, i);
        }
    }

    @Test void callerCollectionsAndReturnedCollectionsAreImmutableSnapshots() {
        var a = node(1);
        var inputs = new ArrayList<>(List.of(a));
        var result = TokenGraph.evaluate(inputs);
        inputs.clear();
        inputs.add(node(2));
        assertEquals(List.of(a), result.perToken(T).heads());
        assertEquals(List.of(node(2)), TokenGraph.evaluate(inputs).perToken(T).heads());
        assertThrows(UnsupportedOperationException.class, () -> result.perToken().clear());
        assertThrows(UnsupportedOperationException.class, () -> result.contradictoryObjectIds().add(id(3)));
        var view = result.perToken(T);
        assertThrows(UnsupportedOperationException.class, () -> view.objects().clear());
        assertThrows(UnsupportedOperationException.class, () -> view.heads().clear());
        assertThrows(UnsupportedOperationException.class, () -> view.currentGroups().clear());
        assertThrows(UnsupportedOperationException.class, () -> view.currentGroups().get(0).clear());
        assertThrows(UnsupportedOperationException.class, () -> view.unresolvedParents().add(new TokenGraph.UnresolvedParent(id(1), id(2))));
        assertThrows(UnsupportedOperationException.class, () -> view.currentValues().clear());
        assertThrows(UnsupportedOperationException.class, () -> view.heads().get(0).token().parents().add(id(2)));
        assertSame(a.token(), view.heads().get(0).token());
        assertSame(ABSENT, view.heads().get(0).token().metadata());
    }

    @Test void twentyThousandNodeChainUsesNoRecursiveTraversal() { deep(false); }
    @Test void twentyThousandNodeCycleUsesNoRecursiveTraversal() { deep(true); }

    private static void deep(boolean cycle) {
        int size = 20_000;
        var input = new ArrayList<ValidatedToken>();
        for (int i = 0; i < size; i++) {
            input.add(i < size - 1 ? node(i, i + 1) : cycle ? node(i, 0) : node(i));
        }
        var result = TokenGraph.evaluate(input);
        var view = result.perToken(T);
        assertEquals(size, view.objects().size());
        assertEquals(1, view.currentGroups().size());
        assertEquals(cycle ? size : 1, view.heads().size());
        assertEquals(input.get(0), view.heads().get(0));
        assertTrue(view.unresolvedParents().isEmpty());
        assertEquals(TokenGraph.CurrentValueState.UNAMBIGUOUS, view.state());
        Collections.reverse(input);
        assertEquals(result, TokenGraph.evaluate(input));
    }
}
