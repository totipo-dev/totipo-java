package dev.totipo.storage.nio;

import dev.totipo.format.VaultBootstrapReplacementStorage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Canonical-only NIO VAULT storage. Complete forced same-directory temporary files
 * support no-replace initial installation or atomic replacement. Lifecycle verification
 * and exact BASE comparison belong to core.
 * Atomic replacement of an existing destination is provider-specific; this backend
 * requires that capability and never falls back to non-atomic overwrite.
 * Containing-directory persistence uses the injected runtime capability. Thread-confined. */
public final class NioVaultBootstrapStorage implements VaultBootstrapReplacementStorage {
    private final Path root;
    private final Operations operations;
    private final Set<Stage> stages = new HashSet<>();
    private boolean closed;
    public static NioVaultBootstrapStorage open(Path root, StorageDurability durability) throws IOException { return open(root, new Operations(durability)); }
    static NioVaultBootstrapStorage open(Path root, Operations operations) throws IOException {
        return new NioVaultBootstrapStorage(NioFiles.root(root), operations);
    }
    private NioVaultBootstrapStorage(Path root, Operations operations) { this.root = root; this.operations = operations; }
    static class Operations {
        private final StorageDurability durability;
        Operations(StorageDurability durability) { this.durability = java.util.Objects.requireNonNull(durability); }
        Path temporary(Path root) throws IOException { return NioFiles.temporary(root, ".totipo-vault-"); }
        int write(FileChannel channel, ByteBuffer bytes) throws IOException { return channel.write(bytes); }
        void syncStage(FileChannel channel) throws IOException { channel.force(true); }
        void link(Path target, Path temp) throws IOException { Files.createLink(target, temp); }
        void move(Path temp, Path target) throws IOException {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        void syncDirectory(Path root) throws IOException { durability.syncDirectory(root); }
    }
    private void usable() throws IOException { if (closed) throw new IOException("STORE_CLOSED"); }
    @Override public InputStream openCanonicalRead() throws IOException {
        usable();
        Path canonical = root.resolve("vault");
        try { NioFiles.regular(canonical); }
        catch (NoSuchFileException absent) { return null; }
        return new ByteArrayInputStream(NioFiles.read(canonical, 88));
    }
    @Override public StagedBootstrap stageInitial(byte[] candidate) throws IOException { return stage(candidate, false); }
    @Override public StagedReplacement stageReplacement(byte[] candidate) throws IOException { return stage(candidate, true); }
    private Stage stage(byte[] candidate, boolean replacement) throws IOException {
        usable();
        if (candidate.length != 87) throw new IllegalArgumentException("EXACT_87_BYTES_REQUIRED");
        byte[] owned = candidate.clone();
        Path temp = null;
        try {
            temp = operations.temporary(root);
            try (var channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                NioFiles.write(channel, owned, operations::write); operations.syncStage(channel);
            }
            var stage = new Stage(temp, replacement); stages.add(stage); return stage;
        } catch (IOException | RuntimeException | Error e) {
            if (temp != null) NioFiles.cleanup(temp);
            throw e;
        } finally { Arrays.fill(owned, (byte) 0); }
    }
    private final class Stage implements StagedBootstrap, StagedReplacement {
        private final Path temp;
        private final boolean replacement;
        private boolean ended, attempted;
        Stage(Path temp, boolean replacement) { this.temp = temp; this.replacement = replacement; }
        private void active() throws IOException { usable(); if (ended) throw new IOException("STAGE_CLOSED"); }
        @Override public InputStream openRead() throws IOException {
            active(); return new ByteArrayInputStream(NioFiles.read(temp, 88));
        }
        private void attempt(boolean replacing) throws IOException {
            active();
            if (attempted || replacing != replacement) throw new IOException("INVALID_INSTALL_ATTEMPT");
            attempted = true;
        }
        @Override public void installInitialDurably() throws IOException {
            attempt(false); operations.link(root.resolve("vault"), temp);
            operations.syncDirectory(root);
        }
        @Override public void replaceCanonicalDurably() throws IOException {
            attempt(true); NioFiles.regular(root.resolve("vault"));
            operations.move(temp, root.resolve("vault")); operations.syncDirectory(root);
        }
        @Override public void close() { ended = true; stages.remove(this); NioFiles.cleanup(temp); }
    }
    @Override public void close() {
        if (closed) return;
        for (var stage : Set.copyOf(stages)) stage.close();
        closed = true;
    }
}
