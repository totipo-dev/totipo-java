package dev.totipo;

import java.util.List;
/** Session-scoped complete semantic identity, including the hidden secret and logical token.
 * Equality/hash codes exclude captured heads and remain stable across states and after close. */
public interface TokenAlternative {
    TokenDescriptor descriptor();
    List<TokenHead> heads();
}
