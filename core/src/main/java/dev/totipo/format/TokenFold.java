package dev.totipo.format;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/** Section 17 construction only. All operation inputs are supplied; nothing is published. */
final class TokenFold {
    private TokenFold() {}

    record Stage(ObjectId objectId, TokenObject token) {
        Stage {
            Objects.requireNonNull(objectId);
            Objects.requireNonNull(token);
        }
    }

    /** Borrows root for key derivation; wipes locally owned keys and canonical plaintext. */
    static List<Stage> build(TokenId tokenId, Collection<ObjectId> originalParents,
                             TokenValue value, TokenMetadata metadata, byte[] root) {
        Objects.requireNonNull(tokenId);
        Objects.requireNonNull(value);
        Objects.requireNonNull(metadata);
        var originals = new TreeSet<>(TokenGraph.OBJECT_ORDER);
        originals.addAll(originalParents); // A frontier is a set; duplicate observations add nothing.
        var remaining = originals.iterator();
        var stages = new ArrayList<Stage>();
        byte[] prk = CryptoSupport.extract(root);
        byte[] idKey = null;
        try {
            idKey = CryptoSupport.idKey(prk);
            ObjectId previous = null;
            do {
                var parents = new TreeSet<>(TokenGraph.OBJECT_ORDER);
                if (previous != null) parents.add(previous);
                int width = previous == null ? 4 : 3;
                for (int i = 0; i < width && remaining.hasNext(); i++) parents.add(remaining.next());
                var token = new TokenObject(tokenId, List.copyOf(parents), value, metadata);
                byte[] semantic = TokenWriter.write(token);
                try {
                    previous = ObjectId.compute(idKey, semantic);
                    stages.add(new Stage(previous, token));
                } finally {
                    Arrays.fill(semantic, (byte) 0);
                }
            } while (remaining.hasNext());
            return List.copyOf(stages);
        } finally {
            Arrays.fill(prk, (byte) 0);
            if (idKey != null) Arrays.fill(idKey, (byte) 0);
        }
    }
}
