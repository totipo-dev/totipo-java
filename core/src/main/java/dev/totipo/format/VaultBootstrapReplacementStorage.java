package dev.totipo.format;

import java.io.IOException;
import java.io.InputStream;

/** Explicit opaque replacement capability; initial publication remains separate. */
public interface VaultBootstrapReplacementStorage extends VaultBootstrapStorage {
    /** Defensively snapshots the supplied bytes into complete separate staging in
     * the same storage/filesystem context needed for atomic replacement. Before
     * return the candidate has crossed its file-durability barrier. Canonical is
     * unchanged. Does not retain/mutate the caller array or validate cryptography.
     * Failure may leave private, nonauthoritative temporary material. */
    StagedReplacement stageReplacement(byte[] exactCandidate) throws IOException;

    interface StagedReplacement extends AutoCloseable {
        /** Stable snapshot of exact completed staged bytes, never null and never
         * a canonical fallback. Caller closes the stream before replacement. */
        InputStream openRead() throws IOException;

        /** Attempt replacement once, atomically where supported, using the staged
         * candidate. Canonical must already exist at replacement time: absence
         * fails without installation. Never truncate/overwrite canonical in place.
         * Success includes required containing-directory durability, but does not
         * imply password-change success: core must reopen/authenticate canonical.
         * Failure may be ambiguous about which representation is present; callers
         * must not infer rollback, restore old bytes, or retry automatically. */
        void replaceCanonicalDurably() throws IOException;

        /** Release resources and best-effort clean private staging. Never delete
         * installed canonical. Cleanup failure after validated publication is
         * non-gating; closing is not a durability barrier. */
        @Override void close() throws IOException;
    }
}
