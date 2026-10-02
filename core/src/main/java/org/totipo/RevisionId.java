package org.totipo;

import java.util.Objects;
public record RevisionId(String hex) {
    public RevisionId { Objects.requireNonNull(hex); if (!hex.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Revision ID"); }
}

