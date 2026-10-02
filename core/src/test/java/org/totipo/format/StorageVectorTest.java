package org.totipo.format;

import org.totipo.conformance.VectorCaseLoader;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class StorageVectorTest {
    @TestFactory List<DynamicTest> everyStorageCase() throws Exception {
        return VectorCaseLoader.storageCases().stream().map(vector ->
                DynamicTest.dynamicTest(vector.context(), () -> StorageVectorChecks.check(vector))).toList();
    }
}
