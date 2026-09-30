package dev.totipo;

/** Session-scoped identity: equal exactly for the same session, token and revision.
 * Equality/hash codes are stable across states and after close; metadata is not identity. */
public interface TokenHead {
    TokenId tokenId();
    RevisionId revision();
    ClientMetadata metadata();
}
