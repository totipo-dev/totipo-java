package dev.totipo.platform.linux;

import dev.totipo.storage.nio.*;

import dev.totipo.format.DiscoverySource;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NativeAccessDisabledTest {
    @Test void readOnlyNioWorksAndDurabilityFailsInDeniedJvm() throws Exception {
        String classpath = String.join(java.io.File.pathSeparator,
                location(LinuxDurability.class), location(NativeAccessDisabledTest.class), location(NioDiscoverySource.class), location(DiscoverySource.class));
        var process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--illegal-native-access=deny", "-cp", classpath, Probe.class.getName()).redirectErrorStream(true).start();
        try {
            assertTrue(process.waitFor(10, TimeUnit.SECONDS));
            assertEquals(0, process.exitValue(), new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        } finally { process.destroyForcibly(); }
    }
    private static String location(Class<?> type) throws Exception {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }
    public static final class Probe {
        public static void main(String[] args) throws Exception {
            Path root = Files.createTempDirectory("native-denied-");
            try {
                Files.createDirectory(root.resolve("objects-v1"));
                Files.write(root.resolve("vault"), new byte[87]);
                try (var snapshot = new NioDiscoverySource(root).snapshot(); var vault = NioVaultBootstrapStorage.open(root, LinuxDurability.open())) {
                    if (snapshot.issue() != DiscoverySource.SnapshotIssue.NONE) throw new AssertionError();
                    try (var read = vault.openCanonicalRead()) { if (read.readAllBytes().length != 87) throw new AssertionError(); }
                    try (var stage = vault.stageReplacement(new byte[87])) { stage.replaceCanonicalDurably(); throw new AssertionError(); }
                    catch (java.io.IOException e) { if (!e.getMessage().equals("NATIVE_ACCESS_DISABLED")) throw e; }
                }
                try { LinuxSecurityMemoryStorage.open(root); throw new AssertionError(); }
                catch (java.io.IOException e) { if (!e.getMessage().equals("NATIVE_ACCESS_DISABLED")) throw e; }
                try (var publisher = NioV1ObjectPublicationStore.open(root, LinuxDurability.open())) {
                    try { publisher.publishDurably(dev.totipo.format.ObjectId.fromFilename("a".repeat(64)), new byte[1024]); throw new AssertionError(); }
                    catch (java.io.IOException e) { if (!e.getMessage().equals("NATIVE_ACCESS_DISABLED")) throw e; }
                }
                // Repeated denied calls leave read-only classes usable, with no initialization poisoning.
                try (var snapshot = new NioDiscoverySource(root).snapshot()) {
                    if (snapshot.candidates().size() != 1) throw new AssertionError();
                }
                try { LinuxDurability.open().syncDirectory(root); throw new AssertionError(); }
                catch (java.io.IOException e) { if (!e.getMessage().equals("NATIVE_ACCESS_DISABLED")) throw e; }
            } finally { Files.deleteIfExists(root.resolve("objects-v1").resolve("a".repeat(64))); Files.deleteIfExists(root.resolve("vault")); Files.deleteIfExists(root.resolve("objects-v1")); Files.delete(root); }
        }
    }
}
