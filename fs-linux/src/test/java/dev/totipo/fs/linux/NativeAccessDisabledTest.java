package dev.totipo.fs.linux;

import dev.totipo.format.DiscoverySource;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NativeAccessDisabledTest {
    @Test void separateDeniedJvmLoadsFallbackAndReportsControlledFailureRepeatedly() throws Exception {
        String classpath = String.join(java.io.File.pathSeparator,
                location(NativeAccessDisabledTest.class), location(LinuxSecureDiscoverySource.class), location(DiscoverySource.class));
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
            Class.forName("dev.totipo.fs.linux.NioDiscoverySource");
            Class.forName("dev.totipo.format.DiscoverySource");
            Class.forName("dev.totipo.fs.linux.LinuxSecureDiscoverySource");
            Class.forName("dev.totipo.fs.linux.LinuxSecurityMemoryStorage");
            Class.forName("dev.totipo.fs.linux.LinuxVaultBootstrapStorage");
            for (int i = 0; i < 2; i++) {
                try {
                    LinuxVaultBootstrapStorage.open(Path.of("/"));
                    throw new AssertionError("Native access must be explicit");
                } catch (java.io.IOException e) {
                    if (!e.getMessage().equals("VAULT_STORAGE_CAPABILITY_NATIVE_ACCESS_DISABLED")) {
                        throw new AssertionError(e);
                    }
                }
            }
            try {
                LinuxSecurityMemoryStorage.open(Path.of("/"));
                throw new AssertionError("Native access must be explicit");
            } catch (java.io.IOException e) {
                if (!e.getMessage().equals("NATIVE_ACCESS_DISABLED")) { throw new AssertionError(e); }
            }
            for (int i = 0; i < 2; i++) {
                var source = new LinuxSecureDiscoverySource(Path.of("/"));
                if (source.capability() != LinuxSecureDiscoverySource.Capability.NATIVE_ACCESS_DISABLED) {
                    throw new AssertionError(source.capability());
                }
                try (var snapshot = source.snapshot()) {
                    if (snapshot.issue() != DiscoverySource.SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS) { throw new AssertionError(); }
                }
            }
        }
    }
}
