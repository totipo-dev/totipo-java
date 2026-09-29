package dev.totipo.format;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Complete canonical semantic plaintext P, without the outer OBJECT_ID. */
record TokenObject(TokenId tokenId, List<ObjectId> parents, TokenValue value, TokenMetadata metadata) {
    static final int MAX_PARENTS = 4;
    static final int MAX_SEMANTIC_BYTES = 77 + 256 + 256 + 128 + (4 + 128) + (4 + 8)
            + MAX_PARENTS * (4 + 32);

    TokenObject {
        Objects.requireNonNull(tokenId);
        parents = List.copyOf(parents);
        Objects.requireNonNull(value);
        Objects.requireNonNull(metadata);
        if (parents.size() > MAX_PARENTS) throw new IllegalArgumentException("Too many parents");
        for (int i = 1; i < parents.size(); i++) {
            if (Arrays.compareUnsigned(parents.get(i - 1).bytes(), parents.get(i).bytes()) >= 0) {
                throw new IllegalArgumentException("Parents must be strictly increasing");
            }
        }
        value.validate();
    }

    @Override public String toString() { return "TokenObject[redacted]"; }
}
