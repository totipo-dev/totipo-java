package org.totipo;

import java.util.List;
/** Session-scoped complete semantic identity, including the hidden secret and logical token.
 * Equality/hash codes exclude captured heads and remain stable across states and after close. */
public interface TokenAlternative {
    /** Semantic-value projection; per-object metadata belongs to each captured head. */
    TokenDescriptor descriptor();
    /** All captured equal-valued heads, each retaining its own exact metadata. */
    List<TokenHead> heads();
}
