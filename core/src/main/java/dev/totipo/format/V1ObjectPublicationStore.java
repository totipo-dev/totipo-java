package dev.totipo.format;

import java.io.IOException;

/**
 * Immutable publication into the bound vault's exact {@code objects-v1/} namespace.
 * Implementations own namespace validation/creation and platform durability barriers;
 * they never receive a root key or interpret object cryptography or semantic content.
 * This interface specifies outcomes, not a staging mechanism.
 */
public interface V1ObjectPublicationStore extends AutoCloseable {
    /** Both outcomes acknowledge the required publication durability barriers. */
    enum PublicationResult { PUBLISHED_NEW, ALREADY_PRESENT_EXACT }

    /**
     * Publish exactly 1024 opaque bytes at {@code objects-v1/<id.filename()>} without
     * overwriting any existing entry. The backend must take an owned snapshot before
     * retaining or using the input; callers must not mutate it during that snapshot.
     * Null arguments are rejected, and a non-1024-byte input is rejected before mutation.
     *
     * PUBLISHED_NEW means the exact immutable target and required file/directory
     * durability barriers are complete. ALREADY_PRESENT_EXACT means an observed regular
     * target equals the supplied exact 1024 bytes, and the backend has completed the
     * durability acknowledgement required for that existing object to satisfy this
     * publication operation. Unlike ordinary discovery, matching bytes alone do not
     * establish publication success. Different bytes, wrong size, symlinks,
     * directories, special files and unsafe/unreadable targets fail closed, never overwrite.
     * No temporary name is authoritative. A successful return is the §36 boundary after
     * which core may durably remember graph knowledge. An IOException may be ambiguous:
     * installed bytes must remain; callers must not infer success or automatically retry.
     *
     * @throws IOException publication or durability cannot be acknowledged, or store closed
     * @throws IllegalArgumentException object length is not exactly 1024
     */
    PublicationResult publishDurably(ObjectId id, byte[] exactObjectBytes) throws IOException;

    /** Release resources without deleting objects. Repeated close is a deterministic no-op;
     * subsequent publication fails. */
    @Override void close() throws IOException;
}
