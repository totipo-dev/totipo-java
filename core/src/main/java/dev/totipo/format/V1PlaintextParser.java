package dev.totipo.format;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Exact v1 structural grammar (§§41–46), entered only after supported routing. */
final class V1PlaintextParser {
    private V1PlaintextParser() {}

    enum Status { STRUCTURALLY_VALID, INVALID_STRUCTURE, NOT_SUPPORTED_V1 }

    enum Reason {
        NONE, ROUTING_PREFIX, SIZE_LIMIT, MISSING_FIELD, UNEXPECTED_FIELD,
        INVALID_LENGTH, INVALID_VALUE, INVALID_UTF8, TRUNCATED_HEADER, TRUNCATED_VALUE, TRAILING_DATA
    }

    record Result(Status status, V1Plaintext plaintext, RoutingParser.Result routing,
                  Reason reason, String message) {}

    /** All body fields are required once. Only parents repeat, in RoutingParser. */
    private enum Field {
        STATUS(0x0103, 1, 1), ISSUER(0x0104, 0, 256), ACCOUNT(0x0105, 0, 256),
        CREDENTIAL(0x0106, 0, 65535), PUBLIC_KEY(0x0201, 65, 65), DISPLAY_NAME(0x0202, 0, 256),
        ALGORITHM(0x0301, 1, 1), DIGITS(0x0302, 1, 1), PERIOD(0x0303, 4, 4),
        SECRET(0x0304, 1, 128), SIGNATURE(0xff01, 0, 72);

        final int tag;
        final int min;
        final int max;

        Field(int tag, int min, int max) {
            this.tag = tag;
            this.min = min;
            this.max = max;
        }
    }

    static Result parse(byte[] semanticBytes) {
        var routing = RoutingParser.parse(semanticBytes);
        switch (routing.outcome()) {
            case MALFORMED:
                return invalid(routing, Reason.ROUTING_PREFIX, "Malformed frozen routing prefix");
            case OPAQUE_ROUTABLE_TOKEN, OPAQUE_ROUTABLE_DEVICE, OPAQUE_UNSCOPED:
                // This return MUST precede all v1 size/body/framing checks. Future tails
                // may be meaningless under v1, and unknown types have no known schema.
                return new Result(Status.NOT_SUPPORTED_V1, null, routing, Reason.NONE,
                        "No supported v1 structure to interpret");
            default:
                break;
        }
        if (semanticBytes.length > 1006) {
            return invalid(routing, Reason.SIZE_LIMIT, "Semantic plaintext exceeds v1 capacity");
        }
        int start = routing.prefixLength();
        var body = new TlvReader(semanticBytes, start, semanticBytes.length - start);
        try {
            V1Plaintext.Token token = null;
            V1Plaintext.Device device = null;
            // Exact sequences enforce required order and single occurrence without maps,
            // sorting, deduplication or a second implementation of the routing prefix.
            if (routing.prefix().objectType() == 1) {
                int status = scalar(field(body, Field.STATUS)).u8();
                if (status != 1 && status != 2) {
                    throw new Invalid(Reason.INVALID_VALUE, "Unknown STATUS enum");
                }
                String issuer = text(field(body, Field.ISSUER));
                String account = text(field(body, Field.ACCOUNT));
                var credential = credential(field(body, Field.CREDENTIAL));
                token = new V1Plaintext.Token(status, issuer, account, credential);
            } else {
                byte[] key = field(body, Field.PUBLIC_KEY);
                String name = text(field(body, Field.DISPLAY_NAME));
                // Point validity and DEVICE_ID derivation are explicitly outside this layer.
                device = new V1Plaintext.Device(key, name);
            }
            byte[] signature = field(body, Field.SIGNATURE);
            end(body);
            return new Result(Status.STRUCTURALLY_VALID,
                    new V1Plaintext(routing.prefix(), token, device, signature), routing, Reason.NONE,
                    "Canonical v1 structure only; authentication and acceptance not established");
        } catch (Invalid e) {
            return invalid(routing, e.reason, e.getMessage());
        } catch (ByteCursor.TruncatedInput e) {
            // Width checks above normally prove every scalar read; retain an intentional
            // failure boundary instead of exposing a low-level exception for protocol data.
            return invalid(routing, Reason.INVALID_LENGTH, "Incomplete fixed-width scalar");
        }
    }

    private static V1Plaintext.Credential credential(byte[] value)
            throws Invalid, ByteCursor.TruncatedInput {
        var fields = new TlvReader(value, 0, value.length);
        int algorithm = scalar(field(fields, Field.ALGORITHM)).u8();
        int digits = scalar(field(fields, Field.DIGITS)).u8();
        long period = scalar(field(fields, Field.PERIOD)).u32be();
        byte[] secret = field(fields, Field.SECRET);
        end(fields);
        if (algorithm < 1 || algorithm > 3 || digits < 6 || digits > 8 || period == 0) {
            throw new Invalid(Reason.INVALID_VALUE, "Credential enum or period outside v1 range");
        }
        return new V1Plaintext.Credential(algorithm, digits, period, secret);
    }

    private static ByteCursor scalar(byte[] value) {
        return new ByteCursor(value, 0, value.length);
    }

    private static byte[] field(TlvReader reader, Field expected) throws Invalid {
        var next = next(reader);
        if (next.status() == TlvReader.Status.END) {
            throw new Invalid(Reason.MISSING_FIELD, "Missing required field " + expected.name());
        }
        var field = next.field();
        if (field.tag() != expected.tag) {
            throw new Invalid(Reason.UNEXPECTED_FIELD,
                    "Noncanonical or forbidden tag; expected " + expected.name());
        }
        if (field.length() < expected.min || field.length() > expected.max) {
            throw new Invalid(Reason.INVALID_LENGTH, "Invalid width/length for " + expected.name());
        }
        return field.value();
    }

    private static TlvReader.Result next(TlvReader reader) throws Invalid {
        var result = reader.next();
        switch (result.status()) {
            case TRUNCATED_HEADER -> throw new Invalid(Reason.TRUNCATED_HEADER, "Incomplete TLV header");
            case TRUNCATED_VALUE -> throw new Invalid(Reason.TRUNCATED_VALUE, "Incomplete TLV value");
            default -> { return result; }
        }
    }

    private static void end(TlvReader reader) throws Invalid {
        if (next(reader).status() != TlvReader.Status.END) {
            throw new Invalid(Reason.TRAILING_DATA, "Unexpected field after final required field");
        }
    }

    private static String text(byte[] value) throws Invalid {
        try {
            // REPORT rejects malformed, overlong, surrogate and truncated encodings.
            // Field metadata limits encoded bytes; do not normalize or prohibit NUL.
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException e) {
            throw new Invalid(Reason.INVALID_UTF8, "Malformed UTF-8 text");
        }
    }

    private static Result invalid(RoutingParser.Result routing, Reason reason, String message) {
        return new Result(Status.INVALID_STRUCTURE, null, routing, reason, message);
    }

    /** Internal control flow only; public-facing results never throw on malformed bytes. */
    private static final class Invalid extends Exception {
        private static final long serialVersionUID = 1L;
        final Reason reason;

        Invalid(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }
    }
}
