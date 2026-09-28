package dev.totipo.conformance;

import java.util.*;
import java.nio.file.*;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class R15ApplicabilityTest {
    @Test void exactPhysicalAndApplicableSelections() throws Exception {
        var all=VectorCaseLoader.allCases();var baseline=VectorCaseLoader.baselineCases();var conditional=VectorCaseLoader.advisoryCases();
        assertEquals(105,all.size());assertEquals(93,baseline.size());assertEquals(12,conditional.size());
        var ids=new HashSet<String>();for(var c:all)assertTrue(ids.add(c.id()));
        var selected=new HashSet<>(baseline);selected.retainAll(conditional);assertTrue(selected.isEmpty());
        selected.addAll(baseline);selected.addAll(conditional);assertEquals(all.stream().map(VectorCaseLoader.Case::id).collect(java.util.stream.Collectors.toSet()),selected.stream().map(VectorCaseLoader.Case::id).collect(java.util.stream.Collectors.toSet()));
        try(var paths=Files.walk(Path.of("src/test/resources/totipo-spec/v1-pre-rc/vectors/cases"))){
            assertEquals(105,paths.filter(p->p.toString().endsWith(".json")).count());
        }
    }
    @Test void baselineProfileAndEveryManifestHashAgree() throws Exception {
        Path root=Path.of("src/test/resources/totipo-spec/v1-pre-rc");
        var manifest=VectorCaseLoader.parse(Files.readString(root.resolve("vectors/manifest.json")),"manifest");
        var profile=VectorCaseLoader.parse(Files.readString(root.resolve("requirements/v1-pre-rc.json")),"profile");
        assertEquals("r15",manifest.field("spec_revision").string());assertEquals("r15",profile.field("spec_revision").string());
        var required=new HashMap<String,String>();
        for(var entry:profile.field("required_cases").array())assertNull(required.put(entry.field("id").string(),entry.field("sha256").string()));
        var baseline=new HashMap<String,String>();
        for(var entry:manifest.field("cases").array()){
            String hash=entry.field("sha256").string();
            assertEquals(hash,HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(root.resolve("vectors").resolve(entry.field("path").string())))));
            if(entry.field("applicability").field("kind").string().equals("baseline"))baseline.put(entry.field("id").string(),hash);
        }
        assertEquals(93,required.size());assertEquals(required,baseline);
    }
    @Test void frozenByteBearingFilesMatchIndependentR14Hashes() throws Exception {
        var lines=Files.readAllLines(Path.of("src/test/resources/frozen-v1-byte-cases.sha256"));
        assertEquals(44,lines.size());
        for(var line:lines){
            var parts=line.split("  ",2);
            assertEquals(parts[0],HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    Files.readAllBytes(Path.of("src/test/resources/totipo-spec/v1-pre-rc",parts[1])))),parts[1]);
        }
    }
}
