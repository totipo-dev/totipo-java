package dev.totipo.format;

import java.io.IOException;
import java.io.InputStream;

/** Opaque synchronized bootstrap storage, separate from local security memory.
 * Implementations bind a safe, fixed canonical namespace; alternate/conflict/temp
 * names are never automatic bootstrap inputs. No method mutates caller arrays.
 * The caller owns this store and closes it after all staged handles and reads.
 */
public interface VaultBootstrapStorage extends AutoCloseable {
    /** Stable bounded-memory snapshot of canonical vault only. Null means proven
     * absence, never unreadability. Caller closes the stream. */
    InputStream openCanonicalRead() throws IOException;

    /** Writes an exact defensive copy of the supplied bytes to separate staging.
     * Before return, all bytes have crossed the required file-durability barrier;
     * canonical storage is untouched. Must not retain the caller's array.
     * Failure may leave private temporary material, never an authoritative input. */
    StagedBootstrap stageInitial(byte[] exactCandidate) throws IOException;

    /** Releases resources; closing is not a durability barrier. */
    @Override void close() throws IOException;

    /** One completed candidate; cryptographic validation belongs to core. */
    interface StagedBootstrap extends AutoCloseable {
        /** Stable snapshot of exactly the completed staged bytes; never null.
         * Caller closes the stream before installation. */
        InputStream openRead() throws IOException;

        /** Install this candidate once with no-replace semantics/equivalent exclusion.
         * An existing canonical pathname must cause failure without replacement.
         * Success includes required containing-directory metadata durability.
         * Failure may be ambiguous: callers must not retry or infer absence.
         * Success still requires core canonical reread and local establishment. */
        void installInitialDurably() throws IOException;

        /** Release resources and best-effort remove uninstalled private material.
         * Never remove installed canonical bytes. Cleanup failure cannot confer authority. */
        @Override void close() throws IOException;
    }
}
