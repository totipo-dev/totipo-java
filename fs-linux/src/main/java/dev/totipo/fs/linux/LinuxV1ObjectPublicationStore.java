package dev.totipo.fs.linux;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Objects;

/** Immutable NIO publication with file force and Linux containing-directory fsync.
 * Named temporary files are nonauthoritative. No overwrite fallback is permitted. */
public final class LinuxV1ObjectPublicationStore implements V1ObjectPublicationStore {
    private final Path root;
    private final Operations operations;
    private boolean closed, rootSyncPending;
    public static LinuxV1ObjectPublicationStore open(Path root) throws IOException { return open(root, new Operations()); }
    static LinuxV1ObjectPublicationStore open(Path root, Operations operations) throws IOException {
        return new LinuxV1ObjectPublicationStore(NioFiles.root(root), operations);
    }
    private LinuxV1ObjectPublicationStore(Path root, Operations operations) { this.root = root; this.operations = operations; }
    static class Operations {
        void at(String point) throws IOException {}
        int write(FileChannel channel, ByteBuffer bytes) throws IOException { return channel.write(bytes); }
        void force(FileChannel channel, String point) throws IOException { at(point); channel.force(true); }
        void sync(Path directory, String point) throws IOException { at(point); LinuxDurability.fsyncDirectory(directory); }
        void syncExisting(Path target) throws IOException { at("existing-file-sync"); LinuxDurability.fsyncFile(target); }
        byte[] readExisting(Path target, String point) throws IOException { at(point); return NioFiles.read(target, 1025); }
        void link(Path target, Path temp) throws IOException {
            at("before-link"); Files.createLink(target, temp); at("after-link");
        }
    }
    @Override public PublicationResult publishDurably(ObjectId id, byte[] exactObjectBytes) throws IOException {
        if (closed) throw new IOException("STORE_CLOSED");
        Objects.requireNonNull(id); Objects.requireNonNull(exactObjectBytes);
        if (exactObjectBytes.length != 1024) throw new IllegalArgumentException("EXACT_1024_BYTES_REQUIRED");
        byte[] owned = exactObjectBytes.clone(); operations.at("snapshot");
        LinuxDurability.requireAvailable();
        Path directory = root.resolve("objects-v1");
        try { operations.at("mkdir"); Files.createDirectory(directory); rootSyncPending = true; }
        catch (FileAlreadyExistsException exists) { NioFiles.directory(directory); }
        // Retain a failed creation barrier for retry on this instance.
        if (rootSyncPending) { operations.sync(root, "root-sync"); rootSyncPending = false; }
        operations.at("temporary");
        Path temp = NioFiles.temporary(directory, ".totipo-object-");
        try (var channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
            NioFiles.write(channel, owned, operations::write);
            operations.force(channel, "stage-sync");
            Path target = directory.resolve(id.filename());
            try { operations.link(target, temp); }
            catch (FileAlreadyExistsException exists) {
                if (!Arrays.equals(owned, operations.readExisting(target, "existing-read"))) throw new IOException("OBJECT_BYTES_MISMATCH");
                operations.syncExisting(target);
                operations.sync(directory, "existing-directory-sync");
                if (!Arrays.equals(owned, operations.readExisting(target, "existing-reread"))) throw new IOException("OBJECT_BYTES_MISMATCH");
                return PublicationResult.ALREADY_PRESENT_EXACT;
            }
            operations.force(channel, "post-link-sync");
            operations.sync(directory, "directory-sync");
            return PublicationResult.PUBLISHED_NEW;
        } finally { NioFiles.cleanup(temp); }
    }
    @Override public void close() { closed = true; }
}
