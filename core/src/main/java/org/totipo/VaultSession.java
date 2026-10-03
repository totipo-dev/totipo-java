package org.totipo;

import java.util.concurrent.Flow;
/** Live owner of vault secrets and storage. See API_DESIGN.md for normative contracts. */
public interface VaultSession extends AutoCloseable {
    VaultFingerprint fingerprint();
    /** Immediate, I/O-free read of the latest emitted state. */
    VaultState state();
    /** Ordered replay-latest publisher with independent coalescing backpressure. */
    Flow.Publisher<VaultState> states();
    /** Non-blocking request for another local observation; requests may coalesce. */
    void requestRefresh();
    /** May block for KDF and configured-store I/O. Uncertainty requires re-observation/reopen.
     * Rewrap retains the same root with fresh salt/nonce. It does not revoke old wrappers,
     * rotate the root or provide recovery from root compromise. */
    PasswordChangeResult changePassword(char[] currentPassword, char[] newPassword);
    /** Rejects entrants, waits for mutating certainty, wipes secrets and completes subscribers. May block.
     * Never waits for subscriber callbacks; safe to call from onNext. A prior fatal termination retains its error. */
    @Override void close();
}
