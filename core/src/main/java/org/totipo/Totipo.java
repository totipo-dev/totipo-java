package org.totipo;

import org.totipo.format.ApplicationVaults;
import org.totipo.spi.TotipoStore;

/** Store-facing entry point for provider integrations. Normal NIO applications use NioTotipo.
 * This library entry point does not claim v1 application conformance.
 * Interactive callers implement creation warnings/confirmation and truthful presentation.
 * Provider integrations can observe possible orphan names before transferring ownership;
 * those unauthenticated names do not veto creation or require exhaustive enumeration.
 * Both calls take ownership of the store, including on failure or invalid password input.
 * A successful session owns it until close; callers must no longer use or close it. */
public final class Totipo {
    private Totipo() {}
    public static OpenResult open(TotipoStore store, char[] password) { return ApplicationVaults.open(store, password); }
    public static CreateVaultResult create(TotipoStore store, char[] password) { return ApplicationVaults.create(store, password); }
}
