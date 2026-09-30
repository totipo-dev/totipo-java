package dev.totipo;

import java.util.List;
public interface MergeToken extends TokenEditor<MergeToken> {
    TokenCompetition competingValues();
    List<MergeSecretChoice> secretChoices();
    MergeToken secret(MergeSecretChoice choice);
    List<String> unresolvedFields();
}

