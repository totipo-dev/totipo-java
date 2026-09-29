package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class TotpVectorTest {
    @Test
    void exactPinnedCategoryAndTrialCount() throws IOException {
        var cases = VectorCaseLoader.totpCases();
        assertEquals(Set.of("v1.totp.rfc6238-sha1.001", "v1.totp.rfc6238-sha256.001",
                "v1.totp.rfc6238-sha512.001"), cases.stream().map(Case::id).collect(Collectors.toSet()));
        for (var c : cases) assertEquals(6, c.data().field("totp").field("rows").array().size(), c.context());
    }

    @TestFactory
    List<DynamicTest> everyPinnedTrial() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        for (var c : VectorCaseLoader.totpCases()) {
            Node totp = c.data().field("totp");
            var rows = totp.field("rows").array();
            for (int i = 0; i < rows.size(); i++) {
                Node row = rows.get(i);
                tests.add(DynamicTest.dynamicTest(c.context() + " row " + i, () -> {
                    assertEquals("PASS", c.expected());
                    assertEquals(BigInteger.ZERO, totp.field("t0").integer());
                    var credential = credential(totp);
                    assertTrue(credential.algorithm() >= 1 && credential.algorithm() <= 3);
                    assertEquals(8, credential.digits());
                    assertEquals(30, credential.period());
                    assertEquals(new int[]{20, 32, 64}[credential.algorithm() - 1], credential.secret().size());
                    assertArrayEquals(totp.field("secret_hex").hex(), credential.secret().bytes());
                    BigInteger time = row.field("unix_time_seconds").integer();
                    assertTrue(time.signum() >= 0);
                    BigInteger counter = Totp.timeStep(time, credential.period());
                    assertEquals(row.field("counter").integer(), counter);
                    assertArrayEquals(row.field("counter_hex").hex(), Totp.encodeCounter(counter));
                    String code = row.field("code").string();
                    assertTrue(code.matches("[0-9]{8}"));
                    assertEquals(code, Totp.generate(credential, time));
                    assertEquals(code, Totp.generate(credential, time.longValueExact()));
                }));
            }
        }
        return tests;
    }

    private static TokenValue.Credential credential(Node totp) {
        return new TokenValue.Credential(totp.field("algorithm").integer().intValueExact(),
                totp.field("digits").integer().intValueExact(),
                totp.field("period").integer().longValueExact(),
                new SecurityBytes(totp.field("secret_hex").hex(), totp.field("secret_hex").hex().length));
    }
}
