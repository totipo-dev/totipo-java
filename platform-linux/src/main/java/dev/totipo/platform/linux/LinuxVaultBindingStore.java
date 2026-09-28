package dev.totipo.platform.linux;

import dev.totipo.format.VaultBindingStore;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;

/** A strict 32-byte authoritative local anchor. No journal or graph data. */
public final class LinuxVaultBindingStore implements VaultBindingStore {
    static final String FILE = "vault-binding-v1.bin";
    private final Path directory;
    private boolean closed;
    private final Operations operations;
    static class Operations { void at(String point) throws IOException {} }
    private LinuxVaultBindingStore(Path directory, Operations operations) { this.directory = directory; this.operations = operations; }
    public static LinuxVaultBindingStore open(Path directory) throws IOException {
        return open(directory, new Operations());
    }
    static LinuxVaultBindingStore open(Path directory, Operations operations) throws IOException {
        LinuxDurability.requireAvailable();
        return new LinuxVaultBindingStore(LocalPrivateFiles.root(directory), operations);
    }
    private void usable() throws IOException { if (closed) { throw new IOException("STORE_CLOSED"); } }
    @Override public Binding read() throws IOException {
        usable();
        byte[] bytes;
        try { bytes = LocalPrivateFiles.read(directory.resolve(FILE), 33); }
        catch (NoSuchFileException e) { return new Binding(State.ABSENT, null); }
        return bytes.length == 32 ? new Binding(State.PRESENT, bytes) : new Binding(State.CORRUPT, null);
    }
    @Override public void create(byte[] binding) throws IOException {
        usable();
        if (binding.length != 32) { throw new IllegalArgumentException("Binding width"); }
        byte[] owned = binding.clone();
        Path temp = LocalPrivateFiles.temporary(directory, ".binding-");
        try {
            try (var channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                var buffer = ByteBuffer.wrap(owned);
                while (buffer.hasRemaining()) {
                    if (channel.write(buffer) <= 0) { throw new IOException("WRITE_NO_PROGRESS"); }
                }
                operations.at("before-force");
                channel.force(true);
                operations.at("after-force");
            }
            operations.at("before-install");
            try { Files.createLink(directory.resolve(FILE), temp); }
            catch (FileAlreadyExistsException e) {
                var existing = read();
                if (existing.state() != State.PRESENT || !Arrays.equals(existing.bytes(), owned)) {
                    throw new IOException("BINDING_MISMATCH_OR_CORRUPT");
                }
            }
            operations.at("after-install");
            LinuxDurability.open().syncDirectory(directory);
            operations.at("after-directory-sync");
        } finally { LocalPrivateFiles.cleanup(temp); }
    }
    @Override public void close() { closed = true; }
}
