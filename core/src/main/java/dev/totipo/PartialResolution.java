package dev.totipo;

/** Frozen original merge resolution, independent of its builder. */
public interface PartialResolution extends AutoCloseable {
    /** May block for configured-store I/O. Does not repeat the semantic new-information gate. */
    PartialSaveResult save();
    @Override void close();
}
