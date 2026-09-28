package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.LinuxDurability;

import dev.totipo.platform.linux.*;
import java.io.*;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.totipo.format.VaultStorageCrashProcess.PASSWORD;

/** Process halt boundaries only; no claim about power loss or hardware caches. */
public final class VaultReplacementCrashProcess {
    static final byte[] NEW_PASSWORD = CryptoSupport.ascii("new-linux-password");
    public static void main(String[] args) throws Exception {
        String mode = args[0]; Path sync = Path.of(args[1]), local = Path.of(args[2]);
        var faults = new ReplacementStorageFaults(LinuxDurability.open());
        var backend = faults.open(sync);
        var memory = LinuxSecurityMemoryStorage.open(local);
        var vault = new VaultBootstrapReplacementStorage() {
            @Override public InputStream openCanonicalRead() throws IOException { return backend.openCanonicalRead(); }
            @Override public StagedBootstrap stageInitial(byte[] bytes) throws IOException { return backend.stageInitial(bytes); }
            @Override public StagedReplacement stageReplacement(byte[] bytes) throws IOException {
                var stage = backend.stageReplacement(bytes);
                if (mode.equals("stage")) Runtime.getRuntime().halt(0);
                return new StagedReplacement() {
                    @Override public InputStream openRead() throws IOException { return stage.openRead(); }
                    @Override public void replaceCanonicalDurably() throws IOException {
                        stage.replaceCanonicalDurably();
                        if (mode.equals("backend")) Runtime.getRuntime().halt(0);
                    }
                    @Override public void close() throws IOException { stage.close(); }
                };
            }
            @Override public void close() throws IOException { backend.close(); }
        };
        var lifecycle = new VaultLifecycle(vault, memory, () -> { throw new AssertionError("rewrap discovery"); },
                bytes -> Arrays.fill(bytes, (byte) 41), new VaultBootstrapWriter(), new VaultUnlocker());
        if (lifecycle.changePassword(PASSWORD, NEW_PASSWORD) != PasswordChangeStatus.SUCCESS) throw new AssertionError("rewrap");
        if (!mode.equals("full")) throw new AssertionError("missed halt boundary");
        Runtime.getRuntime().halt(0);
    }
}
