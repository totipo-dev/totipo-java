package dev.totipo.platform.linux;

import dev.totipo.storage.nio.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LinuxSpecialVaultTest {
    @TempDir Path root;
    static final dev.totipo.format.ObjectId ID = dev.totipo.format.ObjectId.fromFilename("a".repeat(64));
    @Test void boundedCanonicalOnlyAndObservedSpecialFiles() throws Exception {
        try (var store = NioVaultBootstrapStorage.open(root, LinuxDurability.open())) {
            Files.write(root.resolve("vault.tmp"), new byte[87]); assertNull(store.openCanonicalRead());
            Files.write(root.resolve("vault"), new byte[100000]);
            try (var in = store.openCanonicalRead()) { assertEquals(88, in.readAllBytes().length); }
            Files.delete(root.resolve("vault"));
            Files.createSymbolicLink(root.resolve("vault"), Path.of("/dev/zero"));
            assertThrows(IOException.class, store::openCanonicalRead);
            Files.delete(root.resolve("vault")); Files.createDirectory(root.resolve("vault"));
            assertThrows(IOException.class, store::openCanonicalRead);
            Files.delete(root.resolve("vault")); StaticFiles.fifo(root.resolve("vault"));
            assertThrows(IOException.class, store::openCanonicalRead);
        }
    }
}
