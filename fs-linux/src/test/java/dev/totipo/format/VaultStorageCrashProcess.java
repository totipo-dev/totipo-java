package dev.totipo.format;

import dev.totipo.fs.linux.*;
import java.io.*;
import java.nio.file.Path;
import java.util.Arrays;

/** Test-only abrupt process death; this is not a physical power-cut simulation. */
public final class VaultStorageCrashProcess {
    static final byte[] PASSWORD = CryptoSupport.ascii("linux-vault-test");
    static final byte[] ROOT = field(32);
    static byte[] field(int length) { byte[] b = new byte[length]; Arrays.fill(b, (byte) 37); return b; }
    static byte[] candidate() { return new VaultBootstrapWriter().encode(PASSWORD, ROOT, field(16), field(12)); }
    static byte[] binding() { try (var u = VaultUnlockResult.unlocked(ROOT)) { return u.binding(); } }
    static VaultLifecycle lifecycle(VaultBootstrapStorage vault, SecurityMemoryStorage memory, DiscoverySource source) {
        return new VaultLifecycle(vault, memory, source, bytes -> Arrays.fill(bytes, (byte) 37),
                new VaultBootstrapWriter(), new VaultUnlocker());
    }
    public static void main(String[] args) throws Exception {
        String mode = args[0]; Path sync = Path.of(args[1]), local = Path.of(args[2]);
        var faults = new VaultStorageFaults();
        if (mode.equals("pending-published")) faults.afterDirectory = () -> Runtime.getRuntime().halt(0);
        var backend = faults.open(sync);
        if (mode.equals("install") || mode.equals("contend")) {
            var stage = backend.stageInitial(candidate());
            if (mode.equals("contend")) {
                System.out.println("READY"); System.out.flush();
                if (System.in.read() != 'G') throw new AssertionError("barrier");
                try { stage.installInitialDurably(); Runtime.getRuntime().halt(0); }
                catch (IOException e) { Runtime.getRuntime().halt(3); }
            }
            stage.installInitialDurably(); Runtime.getRuntime().halt(0);
        }
        var memory = LinuxSecurityMemoryStorage.open(local);
        VaultBootstrapStorage vault = backend;
        if (mode.equals("stage")) vault = new VaultBootstrapStorage() {
            @Override public InputStream openCanonicalRead() throws IOException { return backend.openCanonicalRead(); }
            @Override public StagedBootstrap stageInitial(byte[] bytes) throws IOException {
                var stage = backend.stageInitial(bytes);
                Runtime.getRuntime().halt(0); return stage;
            }
            @Override public void close() throws IOException { backend.close(); }
        };
        var result = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).createNew(PASSWORD);
        if (result.status() != VaultLifecycleResult.Status.CREATED_ESTABLISHED) throw new AssertionError(result.status());
        Runtime.getRuntime().halt(0);
    }
}
