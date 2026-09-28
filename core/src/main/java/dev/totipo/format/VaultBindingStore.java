package dev.totipo.format;

import java.io.IOException;

/** Authoritative local anchor, separate from synchronized transport. No graph history. */
public interface VaultBindingStore extends AutoCloseable {
    enum State { ABSENT, PRESENT, CORRUPT }
    record Binding(State state, byte[] bytes) {
        public Binding {
            java.util.Objects.requireNonNull(state);
            if (state == State.PRESENT ? bytes == null || bytes.length != 32 : bytes != null) {
                throw new IllegalArgumentException("Invalid binding representation");
            }
            bytes = bytes == null ? null : bytes.clone();
        }
        @Override public byte[] bytes() { return bytes == null ? null : bytes.clone(); }
        @Override public String toString() { return "Binding[" + state + "]"; }
    }
    Binding read() throws IOException;
    /** Durably create if absent; never replace. Existing exact binding may be acknowledged. */
    void create(byte[] exactBinding) throws IOException;
    @Override void close() throws IOException;
}
