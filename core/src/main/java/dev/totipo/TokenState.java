package dev.totipo;

import java.util.List;
public interface TokenState {
    TokenId id();
    List<TokenAlternative> alternatives();
    List<TokenHead> heads();
    List<UnresolvedReference> unresolvedReferences();
    TokenCompetition competingValues();
    boolean hasConflict();
}

