package org.totipo.format;

import java.security.SecureRandom;

/** Internal creation-only seam, with independent draws for each protocol field. */
@FunctionalInterface
interface EntropySource {
    void fill(byte[] destination);

    final class Jdk implements EntropySource {
        private final SecureRandom random = new SecureRandom();
        @Override public void fill(byte[] destination) { random.nextBytes(destination); }
    }
}
