package dev.totipo.format;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GraphTopologyTest {
    static ObjectId id(int n) { return new ObjectId(ByteBuffer.allocate(32).putInt(n).array()); }
    static SecurityBytes identity(int n) { return new SecurityBytes(id(n).bytes(), 32); }
    static AcceptedObject node(boolean token, int id, int identity, int version, int... parents) {
        var ps = Arrays.stream(parents).sorted().mapToObj(GraphTopologyTest::id).toList();
        var status = version == 1 ? SemanticStatus.SUPPORTED_VALID : SemanticStatus.OPAQUE_ROUTABLE;
        return token ? new AcceptedToken(id(id), version, status, identity(identity), ps, identity(99), BigInteger.ZERO,
                version == 1 ? TokenValueFixtures.value() : null)
                : new AcceptedDevice(id(id), version, status, identity(identity), ps, BigInteger.ZERO,
                        version == 1 ? new SecurityBytes(new byte[65], 65) : null);
    }
    static AcceptedSnapshot state(AcceptedObject... objects) {
        var map = new HashMap<ObjectId, AcceptedObject>();
        for (var o : objects) { map.put(o.objectId(), o); }
        return new AcceptedSnapshot(map, false);
    }
    @Test void missingIntermediateSuppliesNoAncestryInEitherFamily() {
        for (boolean token : List.of(true, false)) {
            var a = node(token, 1, 10, 1); var b = node(token, 2, 10, 1, 1); var c = node(token, 3, 10, 1, 2);
            var graph = state(a,b,c).topology(); assertTrue(graph.ancestor(id(1),id(3)));
            graph = state(a,c).topology(); assertFalse(graph.ancestor(id(1),id(3)));
            assertTrue(graph.concurrent(id(1),id(3)));
            assertEquals(ParentEdgeStatus.UNRESOLVED,graph.edgeStatus(id(3),id(2)));
            assertEquals(Set.of(id(1),id(3)),token ? graph.currentTokenHeads(identity(10)) : graph.currentDeviceHeads(identity(10)));
        }
    }
    @Test void wrongIdentityAndTypeNeverSupplyEdges() {
        for (boolean token : List.of(true,false)) {
            var child = node(token,2,10,1,1);
            for (var parent : List.of(node(!token,1,10,1),node(token,1,11,2))) {
                var graph = state(child,parent).topology();
                assertEquals(ParentEdgeStatus.REJECTED,graph.edgeStatus(id(2),id(1)));
                assertFalse(graph.ancestor(id(1),id(2))); assertFalse(graph.concurrent(id(1),id(2)));
            }
        }
    }
    @Test void cycleFailsSafelyWithoutStickySessionState() {
        var cyclic = state(node(true,1,10,1,2),node(true,2,10,2,1));
        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE,cyclic.topology().integrity());
        assertThrows(IllegalStateException.class,()->CurrentTokenValueEvaluator.evaluate(cyclic,identity(10)));
        assertEquals(Set.of(id(1)),state(node(true,1,10,1)).topology().currentTokenHeads(identity(10)));
    }
    @Test void longChainsAreIterative() {
        var map = new HashMap<ObjectId,AcceptedObject>();
        for (int i=1;i<=20000;i++) { var n=node(true,i,10,1,i+1); map.put(n.objectId(),n); }
        var graph = new AcceptedSnapshot(map,false).topology();
        assertTrue(graph.ancestor(id(20000),id(1))); assertEquals(Set.of(id(1)),graph.currentTokenHeads(identity(10)));
    }
}
