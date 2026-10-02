package org.totipo.format;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

/** Immutable authorship facts. Retains no root, derived key, or canonical plaintext. */
final class TokenPublicationPlan {
    private final List<TokenFold.Stage> stages;

    private TokenPublicationPlan(List<TokenFold.Stage> stages) { this.stages = List.copyOf(stages); }

    List<TokenFold.Stage> stages() { return stages; }

    static TokenPublicationPlan planNew(TokenValue value, TokenMetadata metadata, byte[] root) {
        return planNew(value, metadata, new EntropySource.Jdk(), root);
    }

    static TokenPublicationPlan planNew(TokenValue value, TokenMetadata metadata,
                                        EntropySource entropy, byte[] root) {
        byte[] random = new byte[32];
        try {
            entropy.fill(random);
            return planAssertion(new TokenId(random), List.of(), value, metadata, root);
        } finally {
            Arrays.fill(random, (byte) 0);
        }
    }

    /** Parents are explicit causal claims, including unavailable IDs. Duplicates are rejected. */
    static TokenPublicationPlan planAssertion(TokenId tokenId, Collection<ObjectId> parents,
                                              TokenValue value, TokenMetadata metadata, byte[] root) {
        var supplied = List.copyOf(parents);
        if (new HashSet<>(supplied).size() != supplied.size()) {
            throw new IllegalArgumentException("Duplicate operation parent");
        }
        return new TokenPublicationPlan(TokenFold.build(tokenId, supplied, value, metadata, root));
    }
}
