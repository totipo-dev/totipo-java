package dev.totipo.format;

import java.util.HashSet;
import static dev.totipo.format.CurrentTokenValueState.*;

/** §§24.5/25: read-only, no ancestry traversal, crypto, provenance or readiness policy. */
final class CurrentTokenValueEvaluator {
    private CurrentTokenValueEvaluator() {}

    static CurrentTokenValueView evaluate(GraphTopology topology, SecurityBytes tokenId,
                                           CurrentReadableValues readable) {
        var heads = topology.currentTokenHeads(tokenId); // Propagates resolved-cycle failure.
        readable.requireTopology(topology);
        var opaque = new HashSet<ObjectId>();
        var missing = new HashSet<ObjectId>();
        var available = new HashSet<ObjectId>();
        var values = new HashSet<TokenValue>();
        for (var id : heads) {
            var node = (KnownTokenNode) topology.record(id);
            if (node.semanticStatus() == SemanticStatus.OPAQUE_ROUTABLE) {
                opaque.add(id);
            } else {
                var evidence = readable.get(id);
                if (evidence == null) { missing.add(id); }
                else {
                    available.add(id);
                    values.add(evidence.value());
                }
            }
        }
        CurrentTokenValueState state;
        if (heads.isEmpty()) { state = NO_KNOWN_CURRENT_STATE; }
        else if (!opaque.isEmpty()) { state = VALUE_INCOMPLETE_OPAQUE; }
        else if (!missing.isEmpty()) { state = VALUE_INCOMPLETE_UNAVAILABLE; }
        else if (values.size() == 1) { state = SEMANTICALLY_UNAMBIGUOUS; }
        else if (values.size() > 1) { state = WHOLE_STATE_CONFLICT; }
        else { throw new IllegalStateException("Nonempty complete frontier has no readable value"); }
        return new CurrentTokenValueView(state, heads, opaque, missing, available, values);
    }
}
