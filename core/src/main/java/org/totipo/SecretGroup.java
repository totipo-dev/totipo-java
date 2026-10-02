package org.totipo;

import java.util.List;
/** Descriptive secret equality only; not a mutation capability. */
public record SecretGroup(List<TokenAlternative> alternatives) {
    public SecretGroup { alternatives = List.copyOf(alternatives); }
}

