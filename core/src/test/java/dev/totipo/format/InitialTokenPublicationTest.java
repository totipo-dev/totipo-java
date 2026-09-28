package dev.totipo.format;

import dev.totipo.conformance.VectorCaseLoader;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class InitialTokenPublicationTest {
    /** Symbolic acknowledgement contract; concrete signing/reader checks live in writer and integration tests. */
    static void vector(VectorCaseLoader.Case vector) {
        var data=vector.data().field("publication");
        var session=new SnapshotSession(new SecurityBytes(new byte[32],32));
        var key=DeviceWriterTest.KEY;
        var author=new SecurityBytes(P256.deviceId(key),32);
        InitialTokenPublication.Receipt token=null;
        var receipts=new ArrayList<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement>();
        int sequence=1;
        for(var event:data.field("events").array()) {
            switch(event.field("action").string()) {
                case "report-success" -> assertEquals(event.field("success").bool(),TokenPublicationSuccessGate.allows(session,token,key,receipts));
                case "publish-token" -> token=event.field("acknowledged").bool()
                        ? new InitialTokenPublication.Receipt(GraphTopologyTest.identity(1),GraphTopologyTest.id(sequence++),author):null;
                case "restart-workflow" -> {token=null;receipts.clear();}
                case "advertise" -> {
                    if (!event.field("acknowledged").bool() || !event.field("assertion_valid").bool() || !event.field("verified").bool()) continue;
                    var device=event.field("device_id").string().equals(data.field("device_id").string())?author:GraphTopologyTest.identity(4);
                    var publicKey=event.field("public_key").string().equals(data.field("public_key").string())?key:new byte[65];
                    receipts.add(TokenPublicationSuccessGate.acknowledged(new AcceptedDevice(GraphTopologyTest.id(sequence++),1,
                            SemanticStatus.SUPPORTED_VALID,device,List.of(),java.math.BigInteger.ZERO,new SecurityBytes(publicKey,65)),session.binding()));
                }
                default -> fail("Unsupported publication event");
            }
        }
    }
}
