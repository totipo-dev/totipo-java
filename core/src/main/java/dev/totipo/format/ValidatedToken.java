package dev.totipo.format;

import java.util.Objects;

/** Already validated outer identity and complete canonical TOKEN; no observation history. */
record ValidatedToken(ObjectId objectId, TokenObject token) {
    ValidatedToken {
        Objects.requireNonNull(objectId);
        Objects.requireNonNull(token);
    }
}
