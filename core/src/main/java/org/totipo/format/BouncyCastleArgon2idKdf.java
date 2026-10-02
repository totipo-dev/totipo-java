package org.totipo.format;

import java.util.Arrays;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Operation-local lightweight BC Argon2 only; never registers a JCA provider. */
final class BouncyCastleArgon2idKdf implements Argon2idKdf {
    @Override
    public byte[] derive(byte[] password, byte[] salt) {
        if (salt.length != 16) {
            throw new IllegalArgumentException("Argon2 salt must be 16 bytes");
        }
        var builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(65536)
                .withIterations(3)
                .withParallelism(4)
                .withSalt(salt)
                .withSecret(new byte[0])
                .withAdditional(new byte[0]);
        Argon2Parameters parameters = null;
        byte[] key = new byte[32];
        boolean complete = false;
        try {
            parameters = builder.build();
            var generator = new Argon2BytesGenerator();
            generator.init(parameters);
            generator.generateBytes(password, key);
            complete = true;
            return key;
        } finally {
            builder.clear();
            if (parameters != null) {
                parameters.clear();
            }
            if (!complete) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }
}
