package org.totipo.storage.nio;

import org.totipo.format.VaultBootstrapReplacementStorage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;

/** Legacy protocol adapter over the shared opaque staging engine. */
public final class NioVaultBootstrapStorage implements VaultBootstrapReplacementStorage {
    private final Path root;
    private final NioVaultStorage delegate;
    private boolean closed;
    public static NioVaultBootstrapStorage open(Path root, StorageDurability durability) throws IOException {
        return open(root, new Operations(durability));
    }
    static NioVaultBootstrapStorage open(Path root, Operations operations) throws IOException {
        return new NioVaultBootstrapStorage(root, NioVaultStorage.open(root, operations));
    }
    private NioVaultBootstrapStorage(Path root, NioVaultStorage delegate) { this.root = root; this.delegate = delegate; }
    static class Operations extends NioVaultStorage.Operations {
        Operations(StorageDurability durability) { super(durability); }
        @Override void move(Path temp, Path target) throws IOException {
            // Preserve the old low-level capability contract for its existing callers.
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
    }
    @Override public InputStream openCanonicalRead() throws IOException {
        if (closed) throw new IOException("STORE_CLOSED");
        var exact = NioFiles.findExactDirectChild(root, "vault");
        return exact.isEmpty() ? null : new ByteArrayInputStream(NioFiles.read(exact.get(), 88));
    }
    private Stage stage(byte[] bytes, boolean replace) throws IOException {
        if (bytes.length != 87) throw new IllegalArgumentException("EXACT_87_BYTES_REQUIRED");
        return new Stage(delegate.stage(bytes, replace));
    }
    @Override public StagedBootstrap stageInitial(byte[] bytes) throws IOException { return stage(bytes, false); }
    @Override public StagedReplacement stageReplacement(byte[] bytes) throws IOException { return stage(bytes, true); }
    private record Stage(NioVaultStorage.Stage delegate) implements StagedBootstrap, StagedReplacement {
        @Override public InputStream openRead() throws IOException { return delegate.openRead(88); }
        @Override public void installInitialDurably() throws IOException { delegate.installInitialDurably(); }
        @Override public void replaceCanonicalDurably() throws IOException { delegate.replaceCanonicalDurably(); }
        @Override public void close() { delegate.close(); }
    }
    @Override public void close() { closed = true; delegate.close(); }
}
