package dev.totipo;

/** Independent exact-publication capability. Each attempt transfers capability to its result. */
public interface PublicationRetry extends AutoCloseable {
    /** May block for configured-store I/O; never rebases semantics or downgrades uncertainty. */
    RetryResult retryPublication();
    @Override void close();
}
