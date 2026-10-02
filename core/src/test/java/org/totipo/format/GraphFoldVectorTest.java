package org.totipo.format;

import org.totipo.conformance.VectorCaseLoader;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Individual reports use the same consumers as the existing conformance inventory. */
class GraphFoldVectorTest {
    @TestFactory List<DynamicTest> graphCases() throws Exception {
        return VectorCaseLoader.graphCases().stream().map(vector -> DynamicTest.dynamicTest(vector.context(),
                () -> GraphFoldVectorChecks.graph(vector))).toList();
    }

    @TestFactory List<DynamicTest> foldCases() throws Exception {
        return VectorCaseLoader.foldCases().stream().map(vector -> DynamicTest.dynamicTest(vector.context(),
                () -> GraphFoldVectorChecks.fold(vector))).toList();
    }
}
