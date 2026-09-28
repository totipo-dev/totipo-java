package dev.totipo.format;

import java.io.IOException;
import java.util.Arrays;

final class MemoryBindingStore implements VaultBindingStore {
    byte[] bytes;
    public Binding read() { return bytes == null ? new Binding(State.ABSENT,null)
            : bytes.length == 32 ? new Binding(State.PRESENT,bytes) : new Binding(State.CORRUPT,null); }
    public void create(byte[] binding) throws IOException {
        if (binding.length != 32) { throw new IllegalArgumentException(); }
        if (bytes != null && !Arrays.equals(bytes,binding)) { throw new IOException("Binding mismatch"); }
        bytes=binding.clone();
    }
    public void close() {}
}
