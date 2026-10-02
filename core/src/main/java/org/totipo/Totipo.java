package org.totipo;

import org.totipo.format.ApplicationVaults;
import org.totipo.spi.TotipoStore;

/** Store-facing entry point for provider integrations. Normal NIO applications use NioTotipo.
 * Both calls take ownership of the store, including on failure or invalid password input.
 * A successful session owns it until close; callers must no longer use or close it. */
public final class Totipo {
    private Totipo() {}
    public static OpenResult open(TotipoStore store, char[] password) { return ApplicationVaults.open(store, password); }
    public static CreateVaultResult create(TotipoStore store, char[] password) { return ApplicationVaults.create(store, password); }
}
