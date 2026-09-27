package dev.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Exact v1-family consumption in §15 order; never establishes provenance/state acceptance. */
final class EnvelopeReader {
    static final int TAG_BYTES = 16;
    static final int PADDED_BYTES = 1008;
    static final int OBJECT_BYTES = PADDED_BYTES + TAG_BYTES;
    static final int LENGTH_BYTES = 2;
    static final int SEMANTIC_CAPACITY = PADDED_BYTES - LENGTH_BYTES;
    static final int NONCE_BYTES = 12;

    private EnvelopeReader() {}

    enum Status {
        INVALID_ENVELOPE, AUTHENTICATION_FAILED, OBJECT_ID_MISMATCH,
        AUTHENTICATED_FUTURE_TOKEN, AUTHENTICATED_FUTURE_DEVICE, AUTHENTICATED_OPAQUE_UNSCOPED,
        AUTHENTICATED_INVALID_STRUCTURE, AUTHENTICATED_V1_STRUCTURE
    }

    record Result(Status status, RoutingParser.Result routing, V1Plaintext plaintext) {}

    static byte[] nonce(ObjectId id) {
        return Arrays.copyOf(id.bytes(), NONCE_BYTES);
    }

    static byte[] aad(ObjectId id) {
        return CryptoSupport.join(CryptoSupport.ascii("totipo/v1/object"), id.bytes());
    }

    static Result open(String filename, byte[] object, byte[] root) {
        ObjectId id;
        try {
            id = ObjectId.fromFilename(filename);
        } catch (IllegalArgumentException e) {
            return failure(Status.INVALID_ENVELOPE);
        }
        if (object.length != OBJECT_BYTES) {
            return failure(Status.INVALID_ENVELOPE);
        }
        byte[] prk = null;
        byte[] objectRoot = null;
        byte[] key = null;
        byte[] idKey = null;
        byte[] padded = null;
        byte[] semantic = null;
        try {
            prk = CryptoSupport.extract(root);
            objectRoot = CryptoSupport.objectRoot(prk);
            key = CryptoSupport.objectKey(objectRoot, id);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, nonce(id)));
            cipher.updateAAD(aad(id));
            // No incremental output or parsing before successful tag verification.
            padded = cipher.doFinal(object);
            var bytes = new ByteCursor(padded, 0, padded.length);
            int length = bytes.u16be();
            if (padded.length != PADDED_BYTES || length > SEMANTIC_CAPACITY) {
                return failure(Status.INVALID_ENVELOPE);
            }
            semantic = bytes.copy(length);
            while (bytes.remaining() > 0) {
                if (bytes.u8() != 0) {
                    return failure(Status.INVALID_ENVELOPE);
                }
            }
            idKey = CryptoSupport.idKey(prk);
            if (!id.authenticates(idKey, semantic)) {
                return failure(Status.OBJECT_ID_MISMATCH);
            }
            var routing = RoutingParser.parse(semantic);
            return switch (routing.outcome()) {
                case OPAQUE_ROUTABLE_TOKEN -> new Result(Status.AUTHENTICATED_FUTURE_TOKEN, routing, null);
                case OPAQUE_ROUTABLE_DEVICE -> new Result(Status.AUTHENTICATED_FUTURE_DEVICE, routing, null);
                case OPAQUE_UNSCOPED -> new Result(Status.AUTHENTICATED_OPAQUE_UNSCOPED, routing, null);
                case MALFORMED -> new Result(Status.AUTHENTICATED_INVALID_STRUCTURE, routing, null);
                case SUPPORTED_V1_TOKEN, SUPPORTED_V1_DEVICE -> {
                    var parsed = V1PlaintextParser.parse(semantic);
                    yield new Result(parsed.status() == V1PlaintextParser.Status.STRUCTURALLY_VALID
                            ? Status.AUTHENTICATED_V1_STRUCTURE : Status.AUTHENTICATED_INVALID_STRUCTURE,
                            routing, parsed.plaintext());
                }
            };
        } catch (AEADBadTagException e) {
            return failure(Status.AUTHENTICATION_FAILED);
        } catch (ByteCursor.TruncatedInput e) {
            return failure(Status.INVALID_ENVELOPE);
        } catch (GeneralSecurityException e) {
            throw CryptoSupport.unavailable();
        } finally {
            for (byte[] secret : new byte[][]{prk, objectRoot, key, idKey, padded, semantic}) {
                if (secret != null) {
                    Arrays.fill(secret, (byte) 0);
                }
            }
        }
    }

    private static Result failure(Status status) {
        return new Result(status, null, null);
    }
}
