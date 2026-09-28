package dev.totipo.format;

import java.util.HashSet;
import static dev.totipo.format.CurrentTokenValueState.*;

final class CurrentTokenValueEvaluator {
    private CurrentTokenValueEvaluator() {}
    static CurrentTokenValueView evaluate(AcceptedSnapshot snapshot, SecurityBytes tokenId) {
        var graph = snapshot.topology();
        var heads = graph.currentTokenHeads(tokenId);
        var opaque = new HashSet<ObjectId>();
        var values = new HashSet<TokenValue>();
        for (var id : heads) {
            var token = (AcceptedToken) snapshot.object(id);
            if (token.semanticStatus() == SemanticStatus.OPAQUE_ROUTABLE) { opaque.add(id); }
            else { values.add(token.value()); }
        }
        var state = heads.isEmpty() ? EMPTY : !opaque.isEmpty() ? OPAQUE_CURRENT
                : values.size() == 1 ? UNAMBIGUOUS : CONFLICT;
        return new CurrentTokenValueView(state, heads, opaque, values);
    }
}
