package dev.totipo.storage.nio;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Objects;

/** Immutable NIO publication with file force and injected containing-directory durability.
 * Named temporary files are nonauthoritative. No overwrite fallback is permitted. */
public final class NioV1ObjectPublicationStore implements V1ObjectPublicationStore {
    private final Path root;
    private final Operations operations;
    private boolean closed, rootSyncPending;
    public static NioV1ObjectPublicationStore open(Path root, StorageDurability durability) throws IOException { return open(root, new Operations(durability)); }
    static NioV1ObjectPublicationStore open(Path root, Operations operations) throws IOException {
        return new NioV1ObjectPublicationStore(NioFiles.root(root), operations);
    }
    private NioV1ObjectPublicationStore(Path root, Operations operations) { this.root = root; this.operations = operations; }
    static class Operations {
        private final StorageDurability durability;
        Operations(StorageDurability durability) { this.durability = java.util.Objects.requireNonNull(durability); }
        void at(String point) throws IOException {}
        int write(FileChannel channel, ByteBuffer bytes) throws IOException { return channel.write(bytes); }
        void force(FileChannel channel, String point) throws IOException { at(point); channel.force(true); }
        void sync(Path directory, String point) throws IOException { at(point); durability.syncDirectory(directory); }
        void createDirectory(Path directory) throws IOException { Files.createDirectory(directory); }
        byte[] readExisting(Path target, String point) throws IOException { at(point); return NioFiles.read(target, 1025); }
        void link(Path target, Path temp) throws IOException {
            at("before-link"); Files.createLink(target, temp); at("after-link");
        }
    }
    @Override public PublicationResult publish(ObjectId id, byte[] exactObjectBytes) throws IOException {
        if (closed) throw new IOException("STORE_CLOSED");
        Objects.requireNonNull(id); Objects.requireNonNull(exactObjectBytes);
        if (exactObjectBytes.length != 1024) throw new IllegalArgumentException("EXACT_1024_BYTES_REQUIRED");
        byte[] owned = exactObjectBytes.clone(); operations.at("snapshot");

        operations.at("mkdir");
        var namespace = NioFiles.findExactDirectChild(root, "objects-v1");
        if (namespace.isEmpty()) {
            try { operations.createDirectory(root.resolve("objects-v1")); rootSyncPending = true; }
            catch (FileAlreadyExistsException exists) {
                // Only an exactly spelled concurrent winner can be reopened.
                namespace = NioFiles.findExactDirectChild(root, "objects-v1");
                if (namespace.isEmpty()) throw exists;
            }
            if (namespace.isEmpty()) namespace = NioFiles.findExactDirectChild(root, "objects-v1");
        }
        Path directory = namespace.orElseThrow(() -> new IOException("CANONICAL_NAMESPACE_UNAVAILABLE"));
        NioFiles.directory(directory);
        // Retain a failed creation barrier for retry on this instance.
        if (rootSyncPending) { operations.sync(root, "root-sync"); rootSyncPending = false; }
        Path target = directory.resolve(id.filename());
        var existing = NioFiles.findExactDirectChild(directory, id.filename());
        if (existing.isPresent()) {
            if (!Arrays.equals(owned, operations.readExisting(existing.get(), "existing-read"))) throw new IOException("OBJECT_BYTES_MISMATCH");
            return PublicationResult.ALREADY_PRESENT_EXACT;
        }
        operations.at("temporary");
        Path temp = NioFiles.temporary(directory, ".totipo-object-");
        try (var channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
            NioFiles.write(channel, owned, operations::write);
            operations.force(channel, "stage-sync");
            try { operations.link(target, temp); }
            catch (FileAlreadyExistsException exists) {
                Path exact = NioFiles.findExactDirectChild(directory, id.filename()).orElseThrow(() -> exists);
                if (!Arrays.equals(owned, operations.readExisting(exact, "existing-read"))) throw new IOException("OBJECT_BYTES_MISMATCH");
                return PublicationResult.ALREADY_PRESENT_EXACT;
            }
            operations.force(channel, "post-link-sync");
            operations.sync(directory, "directory-sync");
            return PublicationResult.PUBLISHED_NEW;
        } finally { NioFiles.cleanup(temp); }
    }
    @Override public void close() { closed = true; }
}
