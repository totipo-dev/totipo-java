package dev.totipo.storage.nio;

import com.fasterxml.jackson.core.*;
import dev.totipo.format.ObjectId;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class R15PublicationVectorTest {
    @TempDir Path root;
    @Test void localPublicationTrials() throws Exception {
        Path fixture=Path.of(System.getProperty("totipo.test.snapshot"),"vectors/cases/storage/v1.storage.exact-existing-publication.001.json");
        var trials=new ArrayList<Map<String,String>>();Map<String,String> row=null;
        try(var parser=new JsonFactory().createParser(fixture.toFile())){
            while(parser.nextToken()!=null){
                if(parser.currentToken()==JsonToken.START_ARRAY&&"trials".equals(parser.currentName())){
                    while(parser.nextToken()!=JsonToken.END_ARRAY){
                        if(parser.currentToken()==JsonToken.START_OBJECT)row=new HashMap<>();
                        else if(parser.currentToken()==JsonToken.END_OBJECT){trials.add(Map.copyOf(Objects.requireNonNull(row)));row=null;}
                        else if(parser.currentToken().isScalarValue())Objects.requireNonNull(row).put(parser.currentName(),parser.getValueAsString());
                    }
                }
            }
        }
        assertEquals(5,trials.size());int n=0;
        for(var trial:trials){
            Path sync=Files.createDirectory(root.resolve("trial"+n++)),objects=Files.createDirectory(sync.resolve("objects-v1"));
            var id=ObjectId.fromFilename("a".repeat(64));Path target=objects.resolve(id.filename());
            byte[] expected=new byte[1024];Arrays.fill(expected,(byte)42);
            switch(trial.get("existing")){
                case "exact" -> Files.write(target,expected);
                case "different" -> Files.write(target,new byte[1024]);
                case "symlink" -> Files.createSymbolicLink(target,Files.write(sync.resolve("other"),expected));
                case "absent" -> {}
                default -> fail("Unknown trial");
            }
            var durability=new RecordingDurability();if(trial.get("acknowledged").equals("false"))durability.fail="directory";
            try(var store=NioV1ObjectPublicationStore.open(sync,durability)){
                String actual;
                try{actual=store.publish(id,expected).name();}
                catch(IOException e){actual=trial.get("existing").equals("absent")?"UNKNOWN":"FAILED";}
                assertEquals(trial.get("expected"),actual);
                if(trial.get("existing").equals("exact"))assertTrue(durability.events.isEmpty());
                if(trial.get("existing").equals("different"))assertArrayEquals(new byte[1024],Files.readAllBytes(target));
            }
        }
    }
}
