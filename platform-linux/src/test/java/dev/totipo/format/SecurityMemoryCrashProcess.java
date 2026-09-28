package dev.totipo.format;

import dev.totipo.platform.linux.LinuxSecurityMemoryStorage;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.List;

/** Test-only process. All halt branches deliberately bypass close/finally/shutdown hooks. */
public final class SecurityMemoryCrashProcess {
    static SecurityBytes field(int n) { return new SecurityBytes(ByteBuffer.allocate(32).putInt(28,n).array(),32); }
    static ObjectId id(int n) { return new ObjectId(field(n).bytes()); }
    static KnownTokenNode token(int n, List<ObjectId> parents) {
        return new KnownTokenNode(id(n),1,SemanticStatus.SUPPORTED_VALID,field(50000),parents,field(60000),BigInteger.ZERO);
    }
    static KnownTokenNode token(int n) { return token(n,List.of()); }
    public static void main(String[] args) throws Exception {
        var storage=LinuxSecurityMemoryStorage.open(Path.of(args[1]));
        String command=args[0];
        if(command.equals("hold")) {
            System.out.println("READY"); System.out.flush(); System.in.read();
            storage.close(); return;
        }
        if(command.equals("initialize")) { SecurityMemorySession.initializeNew(storage); }
        else if(command.equals("truncate")) { storage.truncateDurably(Long.parseLong(args[2])); }
        else {
            var s=SecurityMemorySession.open(storage);
            byte[] binding=java.util.HexFormat.of().parseHex(args[2]);
            switch(command) {
                case "first" -> require(s.establishFirstOpen(binding));
                case "pending" -> require(s.persistPending(binding));
                case "establish" -> require(s.establishFromPending(binding));
                case "append" -> require(s.commitRecord(token(1)).outcome()==DurableKnowledgeState.Outcome.INSERTED);
                case "multiple" -> {
                    require(s.establishFirstOpen(binding));
                    s.commitRecord(token(1)); s.commitRecord(token(2));
                    s.commitRecord(new KnownDeviceNode(id(3),1,SemanticStatus.SUPPORTED_VALID,field(51),List.of(),
                            BigInteger.ZERO,new SecurityBytes(new byte[65],65)));
                    s.commitRecord(new OpaqueUnscopedRecord(id(4),new SecurityBytes(new byte[1024],1024)));
                    require(s.knowledge().size()==4 && !s.knowledge().knowledgePersistenceBlocked());
                }
                case "unknown" -> {
                    s.commitRecord(token(1)); s.authenticatedInvalidSemantic(id(1));
                    require(!s.knowledge().knowledgePersistenceBlocked());
                    require(s.knowledge().continuity()==LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN);
                }
                case "cycle" -> {
                    s.commitRecord(token(1,List.of(id(2)))); s.commitRecord(token(2,List.of(id(1))));
                    require(!s.knowledge().knowledgePersistenceBlocked());
                    require(s.knowledge().continuity()==LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN);
                }
                default -> throw new IllegalArgumentException(command);
            }
        }
        Runtime.getRuntime().halt(0);
    }
    private static void require(boolean success) { if(!success) throw new AssertionError("commit failed"); }
}
