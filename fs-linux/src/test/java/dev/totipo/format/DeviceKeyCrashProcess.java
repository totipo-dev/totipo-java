package dev.totipo.format;

import dev.totipo.fs.linux.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HexFormat;

/** Abrupt process death and coordinated contenders; no physical power-loss claim. */
public final class DeviceKeyCrashProcess {
    public static void main(String[] args) throws Exception {
        String mode = args[0]; Path local = Path.of(args[1]);
        var faults = new DeviceKeyFaults();
        faults.action = name -> {
            if ((mode.equals("staged") && name.equals("staged-read"))
                    || (mode.equals("linked") && name.equals("post-link-sync"))) Runtime.getRuntime().halt(0);
            if (mode.equals("race") && name.equals("link")) {
                System.out.println("READY"); System.out.flush();
                if (System.in.read() != 'G') throw new IOException("barrier");
            }
        };
        var store = faults.open(local);
        if (mode.equals("load")) {
            var key = store.openExisting(); byte[] message = {1};
            if (!P256.verify(key.publicKeyX963(), message, key.signSha256Ecdsa(message))) throw new AssertionError("signature");
            System.out.println(HexFormat.of().formatHex(P256.deviceId(key.publicKeyX963()))); System.out.flush();
            Runtime.getRuntime().halt(0);
        }
        if (mode.equals("lifecycle")) {
            var memory = LinuxSecurityMemoryStorage.open(local);
            var result = DeviceIdentityLifecycle.createNew(SecurityMemorySession.open(memory).head(), store);
            if (result.status() != DeviceIdentityResult.Status.CREATED_BOUND) throw new AssertionError(result.status());
            System.out.println(HexFormat.of().formatHex(result.deviceId())); System.out.flush();
            Runtime.getRuntime().halt(0);
        }
        if (store.openExisting() != null) throw new AssertionError("not absent");
        try {
            var key = store.createDurably(new byte[32]);
            System.out.println(HexFormat.of().formatHex(key.publicKeyX963())); System.out.flush();
            if (faults.generations != 1) throw new AssertionError("generation retry");
            Runtime.getRuntime().halt(0);
        } catch (IOException e) {
            if (!mode.equals("race") || faults.generations != 1) throw e;
            Runtime.getRuntime().halt(3);
        }
    }
}
