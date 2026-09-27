package dev.totipo.format;

import static dev.totipo.format.TlvTestBytes.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;

/** Test-only byte assembly; every ordinary test evidence goes through real M1 authentication. */
final class TokenValueFixtures {
    private TokenValueFixtures() {}
    static final byte[] ROOT = new byte[32];
    static final SecurityBytes TOKEN = GraphTopologyTest.identity(100);

    static TokenValue value(int status, String issuer, String account, int algorithm, int digits,
                            long period, byte... secret) {
        return new TokenValue(status, issuer, account,
                new TokenValue.Credential(algorithm, digits, period, new SecurityBytes(secret, secret.length)));
    }
    static TokenValue value() { return value(1, "Example", "alice", 1, 6, 30, (byte) 42); }

    static byte[] semantic(int version, SecurityBytes token, List<ObjectId> parents,
                           SecurityBytes author, BigInteger time, byte[] signature, TokenValue value) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(join(field(1, (byte) version), field(2, (byte) 1),
                field(4, ByteBuffer.allocate(2).putShort((short) parents.size()).array())));
        parents.stream().sorted(Comparator.comparing(ObjectId::filename))
                .forEach(p -> out.writeBytes(field(5, p.bytes())));
        out.writeBytes(join(field(6, ByteBuffer.allocate(8).putLong(time.longValue()).array()),
                field(0x0101, token.bytes()), field(0x0102, author.bytes())));
        if (version != 1) {
            out.writeBytes(new byte[]{(byte) 0xff}); // Deliberately uninterpretable v1 tail.
        } else {
            var c = value.credential();
            out.writeBytes(join(field(0x0103, (byte) value.status()),
                    field(0x0104, value.issuer().getBytes(StandardCharsets.UTF_8)),
                    field(0x0105, value.account().getBytes(StandardCharsets.UTF_8)),
                    field(0x0106, join(field(0x0301, (byte) c.algorithm()), field(0x0302, (byte) c.digits()),
                            field(0x0303, ByteBuffer.allocate(4).putInt((int) c.period()).array()),
                            field(0x0304, c.secret().bytes()))), field(0xff01, signature)));
        }
        return out.toByteArray();
    }

    static ReadableTokenValue readable(int nonce, TokenValue value, ObjectId... parents) throws Exception {
        return readable(nonce, TOKEN, value, parents);
    }
    static ReadableTokenValue readable(int nonce, SecurityBytes token, TokenValue value,
                                       ObjectId... parents) throws Exception {
        return ReadableTokenValue.supported(ProvenanceTest.valid(semantic(1, token, List.of(parents),
                GraphTopologyTest.identity(99), BigInteger.valueOf(nonce), new byte[0], value), ROOT));
    }
    static KnownTokenNode opaque(int nonce, ObjectId... parents) throws Exception {
        var opened = ProvenanceTest.authenticate(semantic(2, TOKEN, List.of(parents),
                GraphTopologyTest.identity(99), BigInteger.valueOf(nonce), new byte[0], null), ROOT);
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_FUTURE_TOKEN, opened.status());
        return (KnownTokenNode) AuthenticatedObservation.opaque(opened).orElseThrow().record();
    }
    static GraphTopology graph(ReadableTokenValue... values) {
        return new GraphTopology(GraphTopologyTest.state(java.util.Arrays.stream(values)
                .map(ReadableTokenValue::routing).toArray(DurableRecord[]::new)));
    }
    static CurrentTokenValueView evaluate(GraphTopology graph, ReadableTokenValue... values) {
        return CurrentTokenValueEvaluator.evaluate(graph, TOKEN, new CurrentReadableValues(graph, List.of(values)));
    }
}
