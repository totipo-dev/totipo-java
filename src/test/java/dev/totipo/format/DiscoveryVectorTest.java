package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DiscoveryFixtures.*;

import dev.totipo.conformance.VectorCaseLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class DiscoveryVectorTest {
    @TestFactory
    List<DynamicTest> storageAndFamilyDiscoveryContracts() throws Exception {
        var cases = new ArrayList<>(VectorCaseLoader.storageCases());
        assertEquals(Set.of("v1.storage.objects-v1.001", "v1.storage.nonobject-name-ignored.001",
                "v1.storage.wrong-size-not-opaque.001", "v1.storage.unknown-sibling-ignored.001"),
                cases.stream().map(VectorCaseLoader.Case::id).collect(Collectors.toSet()));
        var family = VectorCaseLoader.futureCases().stream()
                .filter(c -> c.data().field("operation").string().equals("storage")).toList();
        assertEquals(Set.of("v1.future.family-compat-shadow.001", "v1.future.family-no-shadow.001"),
                family.stream().map(VectorCaseLoader.Case::id).collect(Collectors.toSet()));
        cases.addAll(family);
        return cases.stream().map(c -> DynamicTest.dynamicTest(c.context() + " [discovery scope]", () -> {
            var s = c.data().field("storage");
            var expect = s.field("expect");
            var source = vector(s);
            var result = run(source, s.field("root_hex").hex(), DurableKnowledgeState.establishedEmpty());
            var expectedClasses = expect.field("observations").array().stream().collect(Collectors.toMap(
                    n -> n.field("path").string(), n -> n.field("class").string()));
            assertEquals(expectedClasses, result.observations().stream().collect(Collectors.toMap(
                    o -> "objects-v1/" + o.id().filename(), o -> o.classification().name())));
            assertEquals(expectedClasses.keySet(), Set.copyOf(source.reads));
            assertEquals(source.reads.size(), expectedClasses.size());
            assertEquals(expect.field("learned_ids").array().stream().map(n -> n.string()).toList(),
                    result.knowledge().records().keySet().stream().map(ObjectId::filename).sorted().toList());
            assertEquals(expect.field("opaque_unscoped_ids").array().stream().map(n -> n.string()).toList(),
                    result.knowledge().records().values().stream().filter(OpaqueUnscopedRecord.class::isInstance)
                            .map(r -> r.objectId().filename()).sorted().toList());
            assertTrue(result.resourceComplete());
            assertEquals(DiscoveryState.READY, result.discoveryState());
            var readiness = new VaultReadiness(result.knowledge(), result.discoveryState());
            assertEquals(expect.field("authoritative").bool(), readiness.authoritativeVaultReady());
            var query = s.field("query");
            var policy = new TokenOperationPolicy(readiness, result.topology(),
                    new SecurityBytes(query.field("identity").hex(), 32), result.readable());
            var view = expect.field("view");
            assertEquals(view.field("heads").array().stream().map(n -> n.string()).collect(Collectors.toSet()),
                    policy.current().currentHeadIds().stream().map(ObjectId::filename).collect(Collectors.toSet()));
            String valueState = policy.current().state().name();
            assertEquals(view.field("value_state").string(),
                    valueState.equals("SEMANTICALLY_UNAMBIGUOUS") ? "UNAMBIGUOUS" : valueState);
            assertEquals(view.field("ordinary").bool(), policy.ordinaryUse().eligible());
            var selected = policy.candidates().get(ObjectId.fromFilename(query.field("candidate").string()));
            assertNotNull(selected);
            assertEquals(view.field("candidate").bool(), policy.candidateUse(selected).eligible());
            assertEquals(view.field("candidate_warning").bool(), policy.candidateUse(selected).warnings()
                    .contains(CandidateWarning.NOT_ATTESTED_UNIQUELY_CURRENT));
            assertEquals(view.field("integrity_failure").bool(),
                    result.knowledge().continuity() == LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN);
            // author/publication and DEVICE presentation expectations deliberately not claimed.
        })).toList();
    }
}
