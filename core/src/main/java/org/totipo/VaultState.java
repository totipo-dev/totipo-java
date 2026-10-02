package org.totipo;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
/** Immutable observed projection; descriptive reads remain valid after session closure. */
public interface VaultState {
    ObservationProgress observation();
    List<TokenState> tokens();
    Optional<TokenState> token(TokenId id);
    List<VaultDiagnostic> diagnostics();
    CreateToken createToken();
    /** Uses all equal current heads in this state, or the alternative's captured heads when absent. */
    UpdateToken update(TokenAlternative alternative);
    /** Uses exactly this one head; historical same-session references are accepted. */
    UpdateToken update(TokenHead head);
    /** Selects this state's complete current token frontier. */
    MergeToken merge(TokenId tokenId);
    /** Selects exactly the captured heads of the supplied same-session, same-token alternatives. */
    MergeToken merge(Collection<TokenAlternative> alternatives);
    /** Session-backed local crypto, without configured-store I/O. */
    TotpCode generateTotp(TokenAlternative alternative, Instant time);
}
