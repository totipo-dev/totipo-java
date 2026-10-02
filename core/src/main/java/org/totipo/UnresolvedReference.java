package org.totipo;

import java.util.Objects;
public record UnresolvedReference(RevisionId child, RevisionId parent) {
    public UnresolvedReference { Objects.requireNonNull(child); Objects.requireNonNull(parent); }
}

