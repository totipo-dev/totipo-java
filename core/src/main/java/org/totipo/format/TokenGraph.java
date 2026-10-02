package org.totipo.format;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Pure v1 graph derivation over a finite set of already validated identity/content facts. */
final class TokenGraph {
    // Fixed-width lowercase hex has exactly the unsigned lexicographic byte order.
    static final Comparator<ObjectId> OBJECT_ORDER = Comparator.comparing(ObjectId::filename);
    private static final View EMPTY = new View(List.of(), List.of(), List.of(), List.of(), Set.of());

    private TokenGraph() {}

    enum CurrentValueState { EMPTY, UNAMBIGUOUS, CONFLICT }

    record UnresolvedParent(ObjectId child, ObjectId parent) {}

    record View(List<ValidatedToken> objects, List<List<ValidatedToken>> currentGroups,
                List<ValidatedToken> heads, List<UnresolvedParent> unresolvedParents,
                Set<TokenValue> currentValues) {
        View {
            objects = List.copyOf(objects);
            currentGroups = currentGroups.stream().map(List::copyOf).toList();
            heads = List.copyOf(heads);
            unresolvedParents = List.copyOf(unresolvedParents);
            currentValues = immutableSet(currentValues);
        }

        CurrentValueState state() {
            return currentValues.isEmpty() ? CurrentValueState.EMPTY
                    : currentValues.size() == 1 ? CurrentValueState.UNAMBIGUOUS : CurrentValueState.CONFLICT;
        }
    }

    record Result(Set<ObjectId> contradictoryObjectIds, Map<TokenId, View> perToken) {
        Result {
            contradictoryObjectIds = immutableSet(contradictoryObjectIds);
            perToken = Collections.unmodifiableMap(new LinkedHashMap<>(perToken));
        }

        View perToken(TokenId id) { return perToken.getOrDefault(id, EMPTY); }
    }

    static Result evaluate(Collection<ValidatedToken> input) {
        var retained = new HashMap<ObjectId, ValidatedToken>();
        var contradictory = new HashSet<ObjectId>();
        for (var object : input) {
            if (contradictory.contains(object.objectId())) continue;
            var previous = retained.putIfAbsent(object.objectId(), object);
            if (previous != null && !previous.token().equals(object.token())) {
                retained.remove(object.objectId());
                contradictory.add(object.objectId());
            }
        }
        var partitions = new HashMap<TokenId, List<ValidatedToken>>();
        for (var object : retained.values()) {
            partitions.computeIfAbsent(object.token().tokenId(), ignored -> new ArrayList<>()).add(object);
        }
        var identities = new ArrayList<>(partitions.keySet());
        identities.sort((a, b) -> Arrays.compareUnsigned(a.bytes(), b.bytes()));
        var views = new LinkedHashMap<TokenId, View>();
        for (var id : identities) {
            var objects = partitions.get(id);
            objects.sort(Comparator.comparing(ValidatedToken::objectId, OBJECT_ORDER));
            views.put(id, derive(objects));
        }
        var excluded = new ArrayList<>(contradictory);
        excluded.sort(OBJECT_ORDER);
        return new Result(new LinkedHashSet<>(excluded), views);
    }

    /** Kosaraju's two passes use explicit bounded stacks, never the JVM call stack. */
    private static View derive(List<ValidatedToken> objects) {
        int size = objects.size();
        var index = new HashMap<ObjectId, Integer>();
        var edges = new ArrayList<List<Integer>>(size);
        var reverse = new ArrayList<List<Integer>>(size);
        for (int i = 0; i < size; i++) {
            index.put(objects.get(i).objectId(), i);
            edges.add(new ArrayList<>(TokenObject.MAX_PARENTS));
            reverse.add(new ArrayList<>());
        }
        var unresolved = new ArrayList<UnresolvedParent>();
        for (int child = 0; child < size; child++) {
            var object = objects.get(child);
            for (var parent : object.token().parents()) {
                Integer target = index.get(parent); // This index contains only this TOKEN_ID.
                if (target == null) unresolved.add(new UnresolvedParent(object.objectId(), parent));
                else {
                    edges.get(child).add(target);
                    reverse.get(target).add(child);
                }
            }
        }
        int[] stack = new int[size];
        int[] nextEdge = new int[size];
        int[] finish = new int[size];
        int finished = 0;
        boolean[] seen = new boolean[size];
        for (int start = 0; start < size; start++) {
            if (seen[start]) continue;
            int depth = 0;
            stack[depth++] = start;
            seen[start] = true;
            while (depth > 0) {
                int node = stack[depth - 1];
                if (nextEdge[node] < edges.get(node).size()) {
                    int parent = edges.get(node).get(nextEdge[node]++);
                    if (!seen[parent]) {
                        seen[parent] = true;
                        stack[depth++] = parent;
                    }
                } else {
                    depth--;
                    finish[finished++] = node;
                }
            }
        }
        int[] component = new int[size];
        Arrays.fill(component, -1);
        int count = 0;
        for (int i = finished - 1; i >= 0; i--) {
            int start = finish[i];
            if (component[start] != -1) continue;
            int depth = 0;
            stack[depth++] = start;
            component[start] = count;
            while (depth > 0) {
                int node = stack[--depth];
                for (int child : reverse.get(node)) {
                    if (component[child] == -1) {
                        component[child] = count; // Mark on push: at most V stack entries.
                        stack[depth++] = child;
                    }
                }
            }
            count++;
        }
        boolean[] historical = new boolean[count];
        for (int child = 0; child < size; child++) {
            for (int parent : edges.get(child)) {
                // Child -> parent: the TARGET has an incoming descendant edge.
                if (component[child] != component[parent]) historical[component[parent]] = true;
            }
        }
        var groups = new LinkedHashMap<Integer, List<ValidatedToken>>();
        var heads = new ArrayList<ValidatedToken>();
        var values = new LinkedHashSet<TokenValue>();
        for (int i = 0; i < size; i++) {
            if (!historical[component[i]]) {
                var object = objects.get(i);
                groups.computeIfAbsent(component[i], ignored -> new ArrayList<>()).add(object);
                heads.add(object);
                values.add(object.token().value());
            }
        }
        return new View(objects, new ArrayList<>(groups.values()), heads, unresolved, values);
    }

    private static <T> Set<T> immutableSet(Collection<T> values) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }
}
