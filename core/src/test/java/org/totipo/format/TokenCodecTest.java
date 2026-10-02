package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

class TokenCodecTest {
    private static final TokenMetadata ABSENT = new TokenMetadata(Optional.empty(), Optional.empty());

    private static TokenValue value(int status, String issuer, String account,
                                    int algorithm, int digits, long period, byte[] secret) {
        return new TokenValue(status, issuer, account,
                new TokenValue.Credential(algorithm, digits, period, new SecurityBytes(secret, secret.length)));
    }

    private static TokenValue value() { return value(1, "Issuer", "Account", 1, 6, 30, new byte[]{42}); }

    private static TokenObject token(TokenValue value, TokenMetadata metadata) {
        return new TokenObject(new TokenId(new byte[32]), List.of(), value, metadata);
    }

    private static byte[] root() { return TokenWriter.write(token(value(), ABSENT)); }

    @Test void tokenIdIsExactOwnedAndContentEqual() {
        byte[] input = new byte[32];
        var id = new TokenId(input);
        input[0] = 1;
        id.bytes()[1] = 2;
        assertEquals(new TokenId(new byte[32]), id);
        assertEquals(new TokenId(new byte[32]).hashCode(), id.hashCode());
        assertNotEquals(new TokenId(input), id);
        assertNotEquals(new ObjectId(new byte[32]), id);
        for (int length : new int[]{0, 31, 33}) {
            assertThrows(IllegalArgumentException.class, () -> new TokenId(new byte[length]));
        }
    }

    @Test void unsigned64PreservesEveryBoundaryAndUnsignedOrdering() {
        String[] hexes = {"0000000000000000", "0000000000000001", "7fffffffffffffff",
                "8000000000000000", "ffffffffffffffff"};
        String[] decimals = {"0", "1", "9223372036854775807", "9223372036854775808", "18446744073709551615"};
        UInt64 previous = null;
        for (int i = 0; i < hexes.length; i++) {
            byte[] bytes = HexFormat.of().parseHex(hexes[i]);
            var number = UInt64.fromBytes(bytes);
            assertEquals(decimals[i], number.toString());
            assertArrayEquals(bytes, number.bytes());
            assertEquals(number, new UInt64(number.rawBits()));
            assertEquals(number.hashCode(), new UInt64(number.rawBits()).hashCode());
            if (previous != null) assertTrue(previous.compareTo(number) < 0);
            previous = number;
        }
        assertThrows(IllegalArgumentException.class, () -> UInt64.fromBytes(new byte[7]));
        assertThrows(IllegalArgumentException.class, () -> UInt64.fromBytes(new byte[9]));
    }

    @Test void metadataPresenceAndExactTextAffectIdentityButNotTokenValue() {
        var variants = List.of(ABSENT,
                new TokenMetadata(Optional.of(""), Optional.empty()),
                new TokenMetadata(Optional.empty(), Optional.of(new UInt64(0))),
                new TokenMetadata(Optional.empty(), Optional.of(new UInt64(-1))),
                new TokenMetadata(Optional.of(" A\u0000\n e\u0301 😀 "), Optional.of(new UInt64(Long.MIN_VALUE))),
                new TokenMetadata(Optional.of("é"), Optional.empty()),
                new TokenMetadata(Optional.of("e\u0301"), Optional.empty()));
        var bytes = new ArrayList<byte[]>();
        var ids = new ArrayList<ObjectId>();
        for (var metadata : variants) {
            var original = token(value(), metadata);
            byte[] encoded = TokenWriter.write(original);
            var decoded = TokenReader.read(encoded);
            assertEquals(original, decoded);
            assertEquals(value(), decoded.value());
            assertArrayEquals(encoded, TokenWriter.write(decoded));
            var id = V1EnvelopeWriter.seal(new byte[32], encoded).id();
            for (int i = 0; i < bytes.size(); i++) {
                assertFalse(Arrays.equals(bytes.get(i), encoded));
                assertNotEquals(ids.get(i), id);
            }
            bytes.add(encoded);
            ids.add(id);
        }
        assertNotEquals(variants.get(0), variants.get(1));
        assertNotEquals(variants.get(0), variants.get(2));
    }

    @Test void valueEqualityIsExactlyTheSevenFieldTuple() {
        var baseline = value();
        var changed = List.of(
                value(2, "Issuer", "Account", 1, 6, 30, new byte[]{42}),
                value(1, "issuer", "Account", 1, 6, 30, new byte[]{42}),
                value(1, "Issuer", "account", 1, 6, 30, new byte[]{42}),
                value(1, "Issuer", "Account", 2, 6, 30, new byte[]{42}),
                value(1, "Issuer", "Account", 1, 7, 30, new byte[]{42}),
                value(1, "Issuer", "Account", 1, 6, 31, new byte[]{42}),
                value(1, "Issuer", "Account", 1, 6, 30, new byte[]{43}));
        byte[] baselineBytes = TokenWriter.write(token(baseline, ABSENT));
        var baselineId = V1EnvelopeWriter.seal(new byte[32], baselineBytes).id();
        for (var other : changed) {
            assertNotEquals(baseline, other);
            byte[] encoded = TokenWriter.write(token(other, ABSENT));
            assertNotEquals(baselineId, V1EnvelopeWriter.seal(new byte[32], encoded).id());
        }
        assertEquals(baseline, value());
        assertEquals(baseline.hashCode(), value().hashCode());
        var tombstone = changed.get(0);
        assertEquals(baseline.credential(), tombstone.credential());
        assertEquals(Totp.generate(baseline.credential(), 59), Totp.generate(tombstone.credential(), 59));
        assertEquals(tombstone, TokenReader.read(TokenWriter.write(token(tombstone, ABSENT))).value());
    }

    @Test void tokenIdParentsAndMetadataAreOutsideValueEqualityButInsideIdentity() {
        var original = token(value(), ABSENT);
        byte[] differentId = new byte[32];
        differentId[31] = 1;
        var variants = List.of(original,
                new TokenObject(new TokenId(differentId), List.of(), value(), ABSENT),
                new TokenObject(original.tokenId(), List.of(new ObjectId(new byte[32])), value(), ABSENT),
                new TokenObject(new TokenId(differentId), List.of(new ObjectId(new byte[32])), value(),
                        new TokenMetadata(Optional.of("client"), Optional.of(new UInt64(1)))));
        var ids = new java.util.HashSet<ObjectId>();
        for (var variant : variants) {
            assertEquals(original.value(), variant.value());
            assertTrue(ids.add(V1EnvelopeWriter.seal(new byte[32], TokenWriter.write(variant)).id()));
        }
    }

    @Test void parentsAreOwnedUnsignedSortedUniqueAndNeverRepaired() {
        byte[] high = new byte[32]; high[0] = (byte) 0x80;
        byte[] low = new byte[32]; low[0] = 0x7f;
        var smaller = new ObjectId(low);
        var larger = new ObjectId(high);
        var parents = new ArrayList<>(List.of(smaller, larger));
        var object = new TokenObject(new TokenId(new byte[32]), parents, value(), ABSENT);
        parents.clear();
        assertEquals(List.of(smaller, larger), object.parents());
        assertThrows(UnsupportedOperationException.class, () -> object.parents().clear());
        assertEquals(object, TokenReader.read(TokenWriter.write(object)));
        for (var bad : List.of(List.of(larger, smaller), List.of(smaller, smaller),
                List.of(smaller, smaller, smaller, smaller, smaller))) {
            assertThrows(IllegalArgumentException.class,
                    () -> new TokenObject(object.tokenId(), bad, value(), ABSENT));
        }
        byte[] encoded = TokenWriter.write(object);
        assertThrows(IllegalArgumentException.class, () -> TokenReader.read(mutate(encoded, fields -> {
            java.util.Collections.swap(fields, 2, 3); return fields;
        })));
    }

    @Test void fullUnsignedPeriodAndShortExistingSecretsRoundTrip() {
        for (long period : new long[]{1, 0x8000_0000L, 0xffff_ffffL}) {
            for (int length : new int[]{1, 19, 20, 128}) {
                var token = token(value(2, "", "", 3, 8, period, new byte[length]), ABSENT);
                assertEquals(token, TokenReader.read(TokenWriter.write(token)));
            }
        }
    }

    @Test void utf8IsStrictBoundedByBytesAndPreservesControls() {
        for (String text : List.of("ASCII", "é".repeat(128), "😀".repeat(64), "\u0000\n\t\u001f", "e\u0301")) {
            var object = token(value(1, text, text, 1, 6, 30, new byte[]{1}), ABSENT);
            assertEquals(object, TokenReader.read(TokenWriter.write(object)));
        }
        for (String text : List.of("x".repeat(257), "é".repeat(129), "😀".repeat(65), "\ud800", "\udfff")) {
            assertThrows(IllegalArgumentException.class,
                    () -> TokenWriter.write(token(value(1, text, "", 1, 6, 30, new byte[]{1}), ABSENT)));
            assertThrows(IllegalArgumentException.class,
                    () -> TokenWriter.write(token(value(1, "", text, 1, 6, 30, new byte[]{1}), ABSENT)));
        }
        for (String name : List.of("x".repeat(129), "é".repeat(65), "\ud800")) {
            assertThrows(IllegalArgumentException.class,
                    () -> TokenWriter.write(token(value(), new TokenMetadata(Optional.of(name), Optional.empty()))));
        }
        for (String hex : List.of("80", "c080", "eda080", "f4908080", "e282", "ff")) {
            for (int tag : new int[]{5, 6, 11}) {
                byte[] malformed = HexFormat.of().parseHex(hex);
                byte[] bytes = tag == 11 ? append(root(), new TlvField(tag, malformed)) : replace(root(), tag, malformed);
                assertThrows(IllegalArgumentException.class, () -> TokenReader.read(bytes));
            }
        }
    }

    @Test void modelRejectsEveryNumericAndSecretBound() {
        for (int status : new int[]{0, 3, 255}) reject(value(status, "", "", 1, 6, 30, new byte[]{1}));
        for (int algorithm : new int[]{0, 4, 255}) reject(value(1, "", "", algorithm, 6, 30, new byte[]{1}));
        for (int digits : new int[]{0, 5, 9, 255}) reject(value(1, "", "", 1, digits, 30, new byte[]{1}));
        for (long period : new long[]{-1, 0, 0x1_0000_0000L}) reject(value(1, "", "", 1, 6, period, new byte[]{1}));
        for (int length : new int[]{0, 129}) reject(value(1, "", "", 1, 6, 30, new byte[length]));
    }

    private static void reject(TokenValue value) {
        assertThrows(IllegalArgumentException.class, () -> TokenWriter.write(token(value, ABSENT)));
    }

    @Test void maximumArithmeticMatchesActualEncodingAndFixedCapacity() {
        int mandatoryFraming = 9 * 4;
        int mandatoryFixedValues = 32 + 2 + 1 + 1 + 1 + 4;
        assertEquals(77, mandatoryFraming + mandatoryFixedValues);
        int nonParents = mandatoryFraming + mandatoryFixedValues + 256 + 256 + 128 + 4 + 128 + 4 + 8;
        assertEquals(861, nonParents);
        assertEquals(4, TokenObject.MAX_PARENTS);
        assertEquals(1005, nonParents + 4 * 36);
        assertEquals(1005, TokenObject.MAX_SEMANTIC_BYTES);
        assertEquals(1008, EnvelopeReader.PADDED_BYTES);
        assertEquals(2, EnvelopeReader.LENGTH_BYTES);
        assertEquals(1006, EnvelopeReader.SEMANTIC_CAPACITY);
        var parents = new ArrayList<ObjectId>();
        for (int i = 0; i < 4; i++) { byte[] p = new byte[32]; p[31] = (byte) i; parents.add(new ObjectId(p)); }
        var object = new TokenObject(new TokenId(new byte[32]), parents,
                value(2, "i".repeat(256), "a".repeat(256), 3, 8, 0xffff_ffffL, new byte[128]),
                new TokenMetadata(Optional.of("c".repeat(128)), Optional.of(new UInt64(-1))));
        byte[] encoded = TokenWriter.write(object);
        assertEquals(1005, encoded.length);
        assertEquals(object, TokenReader.read(encoded));
        var sealed = V1EnvelopeWriter.seal(new byte[32], encoded);
        assertEquals(1024, sealed.bytes().length);
        assertArrayEquals(encoded, EnvelopeReader.open(sealed.id().filename(), sealed.bytes(), new byte[32]).semanticBytes());
    }

    @Test void truncatedHeadersAndHostileLengthsReject() {
        byte[] valid = root();
        for (int length = 0; length < valid.length; length++) {
            byte[] truncated = Arrays.copyOf(valid, length);
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(truncated));
        }
        for (byte[] malformed : List.of(new byte[]{0}, new byte[]{0, 1}, new byte[]{0, 1, 0},
                new byte[]{0, 1, 0, 32, 1}, new byte[]{0, 1, (byte) 0xff, (byte) 0xff})) {
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(malformed));
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(CryptoSupport.join(valid, malformed)));
        }
    }

    @Test void everyFixedWidthAndParentCountBoundaryRejects() {
        int[][] fixed = {{1, 32}, {2, 2}, {4, 1}, {7, 1}, {8, 1}, {9, 4}};
        for (int[] f : fixed) {
            for (int width : new int[]{f[1] - 1, f[1] + 1}) {
                byte[] malformed = replace(root(), f[0], new byte[width]);
                assertThrows(IllegalArgumentException.class, () -> TokenReader.read(malformed));
            }
        }
        for (int width : new int[]{0, 7, 9}) {
            byte[] malformed = append(root(), new TlvField(12, new byte[width]));
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(malformed));
        }
        for (int count : new int[]{1, 4, 5, 65535}) {
            byte[] malformed = replace(root(), 2, new byte[]{(byte) (count >>> 8), (byte) count});
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(malformed));
        }
        for (int width : new int[]{31, 32, 33}) {
            byte[] extra = mutate(root(), fields -> { fields.add(2, new TlvField(3, new byte[width])); return fields; });
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(extra)); // Count zero.
            if (width != 32) {
                byte[] wrongWidth = replace(extra, 2, new byte[]{0, 1});
                assertThrows(IllegalArgumentException.class, () -> TokenReader.read(wrongWidth));
            }
        }
    }

    @Test void optionalDuplicatesWrongOrderMissingAndExtraFieldsReject() {
        var name = new TlvField(11, new byte[0]);
        var time = new TlvField(12, new byte[8]);
        for (var fields : List.of(List.of(name, name), List.of(time, time), List.of(time, name),
                List.of(new TlvField(13, new byte[0])), List.of(new TlvField(10, new byte[]{1})))) {
            byte[] malformed = mutate(root(), list -> { list.addAll(fields); return list; });
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(malformed));
        }
        for (int tag : new int[]{1, 2, 4, 5, 6, 7, 8, 9, 10}) {
            byte[] missing = mutate(root(), fields -> { fields.removeIf(f -> f.tag() == tag); return fields; });
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(missing));
            byte[] duplicate = mutate(root(), fields -> { fields.add(0, fields.stream().filter(f -> f.tag() == tag).findFirst().orElseThrow()); return fields; });
            assertThrows(IllegalArgumentException.class, () -> TokenReader.read(duplicate));
        }
    }

    @Test void secretOwnershipAndScratchDisposalDoNotDestroyLiveModel() {
        byte[] secret = {42};
        var object = token(value(1, "", "", 1, 6, 30, secret), ABSENT);
        secret[0] = 0;
        object.value().credential().secret().bytes()[0] = 0;
        byte[] encoded = TokenWriter.write(object);
        var decoded = TokenReader.read(encoded);
        Arrays.fill(encoded, (byte) 0);
        assertEquals(object, decoded);
        assertArrayEquals(new byte[]{42}, decoded.value().credential().secret().bytes());
        assertEquals("TokenObject[redacted]", decoded.toString());
        assertEquals("TokenValue[redacted]", decoded.value().toString());
        assertEquals("Credential[redacted]", decoded.value().credential().toString());
        var field = new TlvField(10, new byte[]{42});
        byte[] owned = field.value();
        field.clear();
        assertArrayEquals(new byte[]{42}, owned);
        assertArrayEquals(new byte[]{0}, field.value());
        var writer = new TlvWriter();
        writer.field(10, owned);
        byte[] output = writer.bytes();
        writer.close();
        assertArrayEquals(new byte[]{0, 10, 0, 1, 42}, output);
        assertThrows(IllegalStateException.class, writer::bytes);
    }

    private static byte[] append(byte[] input, TlvField field) {
        return mutate(input, fields -> { fields.add(field); return fields; });
    }

    private static byte[] replace(byte[] input, int tag, byte[] value) {
        return mutate(input, fields -> {
            fields.replaceAll(f -> f.tag() == tag ? new TlvField(tag, value) : f);
            return fields;
        });
    }

    /** Uses the production framing reader/writer; changes fields without a second parser. */
    private static byte[] mutate(byte[] input, UnaryOperator<List<TlvField>> change) {
        var reader = new TlvReader(input, 0, input.length);
        var fields = new ArrayList<TlvField>();
        for (var result = reader.next(); result.status() != TlvReader.Status.END; result = reader.next()) {
            assertEquals(TlvReader.Status.FIELD, result.status());
            fields.add(result.field());
        }
        try (var writer = new TlvWriter()) {
            for (var field : change.apply(fields)) writer.field(field.tag(), field.value());
            return writer.bytes();
        }
    }
}
