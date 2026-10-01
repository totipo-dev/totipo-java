package dev.totipo.storage.nio;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Shared opaque staging engine. Protocol sizes and lifecycle policy belong to core. */
final class NioVaultStorage {
    private final Path root;
    private final Operations operations;
    private final Set<Stage> stages = new HashSet<>();
    private boolean closed;
    public static NioVaultStorage open(Path root, StorageDurability durability) throws IOException { return open(root, new Operations(durability)); }
    static NioVaultStorage open(Path root, Operations operations) throws IOException {
        return new NioVaultStorage(NioFiles.root(root), operations);
    }
    private NioVaultStorage(Path root, Operations operations) { this.root = root; this.operations = operations; }
    static class Operations {
        private final StorageDurability durability;
        Operations(StorageDurability durability) { this.durability = java.util.Objects.requireNonNull(durability); }
        Path temporary(Path root) throws IOException { return NioFiles.temporary(root, ".totipo-vault-"); }
        int write(FileChannel channel, ByteBuffer bytes) throws IOException { return channel.write(bytes); }
        void syncStage(FileChannel channel) throws IOException { channel.force(true); }
        void link(Path target, Path temp) throws IOException { Files.createLink(target, temp); }
        void atomicMove(Path temp, Path target) throws IOException {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        void move(Path temp, Path target) throws IOException {
            try { atomicMove(temp, target); }
            catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        void syncDirectory(Path root) throws IOException { durability.syncDirectory(root); }
    }
    private void usable() throws IOException { if (closed) throw new IOException("STORE_CLOSED"); }
    Stage stage(byte[] candidate, Boolean replacement) throws IOException {
        usable();
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
    final class Stage implements AutoCloseable {
        private final Path temp;
        private final Boolean replacement;
        private boolean ended, attempted;
        boolean mutationEntered;
        Stage(Path temp, Boolean replacement) { this.temp = temp; this.replacement = replacement; }
        private void active() throws IOException { usable(); if (ended) throw new IOException("STAGE_CLOSED"); }
        public InputStream openRead(int limit) throws IOException {
            active(); return new ByteArrayInputStream(NioFiles.read(temp, limit));
        }
        dev.totipo.spi.BoundedRead readBack(int expectedBytes) {
            if (ended || attempted || closed) throw new IllegalStateException("STAGE_CONSUMED");
            return NioReads.child(temp.getParent(), temp.getFileName().toString(), expectedBytes);
        }
        void requireActive() {
            if (ended || attempted || closed) throw new IllegalStateException("STAGE_CONSUMED");
        }
        private void attempt(boolean replacing) throws IOException {
            active();
            if (attempted || (replacement != null && replacing != replacement)) throw new IOException("INVALID_INSTALL_ATTEMPT");
            attempted = true;
        }
        public void installInitialDurably() throws IOException {
            attempt(false);
            mutationEntered = true;
            try { operations.link(root.resolve("vault"), temp); }
            catch (FileAlreadyExistsException exists) { mutationEntered = false; throw exists; }
            operations.syncDirectory(root);
        }
        public void replaceCanonicalDurably() throws IOException {
            attempt(true);
            Path canonical = NioFiles.findExactDirectChild(root, "vault")
                    .orElseThrow(() -> new NoSuchFileException("vault"));
            NioFiles.regular(canonical);
            mutationEntered = true;
            operations.move(temp, canonical); operations.syncDirectory(root);
        }
        @Override public void close() { ended = true; stages.remove(this); NioFiles.cleanup(temp); }
    }
    public void close() {
        if (closed) return;
        for (var stage : Set.copyOf(stages)) stage.close();
        closed = true;
    }
}
