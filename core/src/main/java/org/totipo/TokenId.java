package org.totipo;

import java.util.Objects;
public record TokenId(String hex) {
    public TokenId { Objects.requireNonNull(hex); if (!hex.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Token ID"); }
}

