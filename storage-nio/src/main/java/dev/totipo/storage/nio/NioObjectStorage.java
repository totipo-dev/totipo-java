package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Objects;

/** Immutable NIO publication with file force and injected containing-directory durability.
 * Named temporary files are nonauthoritative. No overwrite fallback is permitted. */
final class NioObjectStorage {
    private final Path root;
    private final Operations operations;
    private boolean closed;
    boolean mutationEntered;
    static final class Different extends IOException {
        private static final long serialVersionUID = 1L;
    }
    public static NioObjectStorage open(Path root, StorageDurability durability) throws IOException { return open(root, new Operations(durability)); }
    static NioObjectStorage open(Path root, Operations operations) throws IOException {
        return new NioObjectStorage(NioFiles.root(root), operations);
    }
    private NioObjectStorage(Path root, Operations operations) { this.root = root; this.operations = operations; }
    static class Operations {
        private final StorageDurability durability;
        Operations(StorageDurability durability) { this.durability = java.util.Objects.requireNonNull(durability); }
        void at(String point) throws IOException {}
        int write(FileChannel channel, ByteBuffer bytes) throws IOException { return channel.write(bytes); }
        void force(FileChannel channel, String point) throws IOException { at(point); channel.force(true); }
        void sync(Path directory, String point) throws IOException { at(point); durability.syncDirectory(directory); }
        void createDirectory(Path directory) throws IOException { Files.createDirectory(directory); }
        byte[] readExisting(Path target, String point, int limit) throws IOException { at(point); return NioFiles.read(target, limit); }
        void link(Path target, Path temp) throws IOException {
            Files.createLink(target, temp);
        }
    }
    boolean publish(String name, byte[] exactObjectBytes, boolean acknowledgeExisting) throws IOException {
        mutationEntered = false;
        if (closed) throw new IOException("STORE_CLOSED");
        Objects.requireNonNull(name); Objects.requireNonNull(exactObjectBytes);
        byte[] owned = exactObjectBytes.clone(); operations.at("snapshot");

        operations.at("mkdir");
        Path directory = NioObjectScan.namespace(root);
        if (directory == null) {
            try { operations.createDirectory(root.resolve("objects-v1")); }
            catch (FileAlreadyExistsException exists) {
                // Only an exactly spelled concurrent winner can be reopened.
                directory = NioObjectScan.namespace(root);
                if (directory == null) throw new NioNamespace.Collision(root.resolve("objects-v1").toString());
            }
            if (directory == null) directory = NioObjectScan.namespace(root);
        }
        if (directory == null) throw new IOException("CANONICAL_NAMESPACE_UNAVAILABLE");
        Path target = directory.resolve(name);
        var existing = NioFiles.findExactDirectChild(directory, name);
        if (existing.isPresent()) {
            if (!Arrays.equals(owned, operations.readExisting(existing.get(), "existing-read", owned.length + 1))) throw new Different();
            if (acknowledgeExisting) acknowledge(directory, name, owned);
            return false;
        }
        // Every new publication establishes namespace durability, even after another provider closes.
        // Failure here is definite: the object-target mutation boundary has not been entered.
        operations.sync(root, "root-sync");
        operations.at("temporary");
        Path temp = NioFiles.temporary(directory, ".totipo-object-");
        try (var channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
            NioFiles.write(channel, owned, operations::write);
            operations.force(channel, "stage-sync");
            operations.at("before-link");
            try { mutationEntered = true; operations.link(target, temp); }
            catch (FileAlreadyExistsException exists) {
                mutationEntered = false;
                Path exact = NioFiles.findExactDirectChild(directory, name)
                        .orElseThrow(() -> new NioNamespace.Collision(target.toString()));
                if (!Arrays.equals(owned, operations.readExisting(exact, "existing-read", owned.length + 1))) throw new Different();
                if (acknowledgeExisting) acknowledge(directory, name, owned);
                return false;
            }
            operations.at("after-link");
            if (acknowledgeExisting && NioFiles.findExactDirectChild(directory, name).isEmpty())
                throw new IOException("EXACT_TARGET_UNAVAILABLE");
            operations.force(channel, "post-link-sync");
            operations.sync(directory, "directory-sync");
            return true;
        } finally { NioFiles.cleanup(temp); }
    }
    private void acknowledge(Path directory, String name, byte[] owned) throws IOException {
        // A failed exact retry must never masquerade as a fresh durability acknowledgement.
        mutationEntered = true;
        NioFiles.directory(directory);
        Path exact = NioFiles.findExactDirectChild(directory, name)
                .orElseThrow(() -> new IOException("EXACT_TARGET_UNAVAILABLE"));
        NioFiles.regular(exact);
        try (var channel = FileChannel.open(exact, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            operations.force(channel, "existing-force");
        }
        operations.sync(directory, "existing-directory-sync");
        operations.sync(root, "existing-root-sync");
        if (!Arrays.equals(owned, operations.readExisting(exact, "existing-confirm", owned.length + 1)))
            throw new IOException("EXACT_TARGET_CHANGED");
    }
    public void close() { closed = true; }
}
