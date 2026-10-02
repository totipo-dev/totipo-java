package org.totipo.storage.nio;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class NioDurabilityTest {
    @TempDir Path root;

    @Test void localProviderCapabilityIsReportedHonestly() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("build"), "durability-");
        try {
            checkLocalCapability(directory);
        } finally { Files.delete(directory); }
    }

    private static void checkLocalCapability(Path directory) throws Exception {
        Exception unsupported = null;
        try (var channel = FileChannel.open(directory, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException | SecurityException e) {
            unsupported = e;
        }
        if (unsupported == null) {
            new NioDurability().syncDirectory(directory);
            System.out.println("Directory-channel force accepted on test filesystem");
        } else {
            var failure = assertThrows(IOException.class, () -> new NioDurability().syncDirectory(directory));
            assertTrue(failure.getMessage().contains("Directory-channel force unavailable"));
            assertNotNull(failure.getCause());
        }
    }

    @Test void rejectsFilesMissingPathsAndFinalSymlinks() throws Exception {
        Path file = Files.write(root.resolve("file"), new byte[1]);
        var durability = new NioDurability();
        assertThrows(IOException.class, () -> durability.syncDirectory(file));
        assertThrows(IOException.class, () -> durability.syncDirectory(root.resolve("missing")));
        Path link = root.resolve("link");
        try { Files.createSymbolicLink(link, root); }
        catch (UnsupportedOperationException | IOException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "Symlink fixture unavailable: " + e);
        }
        assertThrows(IOException.class, () -> durability.syncDirectory(link));
    }

    @Test void providerWithoutDirectoryChannelsFailsWithIOException() throws Exception {
        URI uri = URI.create("jar:" + root.resolve("store.zip").toUri());
        try (var zip = FileSystems.newFileSystem(uri, Map.of("create", "true"))) {
            Path directory = Files.createDirectory(zip.getPath("/objects-v1"));
            var failure = assertThrows(IOException.class, () -> new NioDurability().syncDirectory(directory));
            assertTrue(failure.getMessage().contains("Directory-channel force unavailable"));
            assertNotNull(failure.getCause());
        }
    }
}
