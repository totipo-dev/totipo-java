package dev.totipo.format;

import java.io.IOException;

/** Immutable publication into the configured durable store's objects-v1 namespace.
 * Acknowledgement is local to this configured store. */
public interface V1ObjectPublicationStore extends AutoCloseable {
    enum PublicationResult { PUBLISHED_NEW, ALREADY_PRESENT_EXACT }
    /** Publish an owned copy of exactly 1024 bytes without overwrite.
     * Existing success requires a canonical ordinary regular file with the exact bytes.
     * New success requires the backend's file/storage and namespace persistence work.
     * Exact-existing success is read-only and requires no fresh persistence barrier.
     * An IOException or absent acknowledgement is ambiguous; leave installed bytes in place.
     * A later retry or discovery is permitted without reconciliation.
     * @throws IOException publication cannot be acknowledged, or store closed
     * @throws IllegalArgumentException object length is not exactly 1024
     */
    PublicationResult publish(ObjectId id, byte[] exactObjectBytes) throws IOException;
    /** Release resources without deleting objects; repeated close is harmless. */
    @Override void close() throws IOException;
}
