package org.totipo.format;

import org.totipo.conformance.VectorCaseLoader;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class VaultVectorTest {
    @TestFactory List<DynamicTest> everyPinnedVaultCase() throws Exception {
        return VectorCaseLoader.vaultCases().stream().map(vector ->
                DynamicTest.dynamicTest(vector.context(), () -> VaultVectorChecks.check(vector))).toList();
    }
}
