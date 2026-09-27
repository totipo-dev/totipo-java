package dev.totipo.format;

/** Structural plaintext only: neither authenticated, provenance-verified nor accepted. */
record V1Plaintext(RoutingPrefix routing, Token token, Device device, byte[] signature) {
    V1Plaintext {
        signature = signature.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    record Token(int status, String issuer, String account, Credential credential) {}

    record Credential(int algorithm, int digits, long period, byte[] secret) {
        Credential {
            secret = secret.clone();
        }

        @Override
        public byte[] secret() {
            return secret.clone();
        }

        @Override
        public String toString() {
            return "Credential[redacted]";
        }
    }

    record Device(byte[] publicKey, String displayName) {
        Device {
            publicKey = publicKey.clone();
        }

        @Override
        public byte[] publicKey() {
            return publicKey.clone();
        }
    }
}
