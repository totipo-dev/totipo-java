package org.totipo.format;

/** Only the fixed Totipo operation. Borrows inputs synchronously; returns an owned 32-byte key. */
@FunctionalInterface
interface Argon2idKdf {
    byte[] derive(byte[] password, byte[] salt);
}
