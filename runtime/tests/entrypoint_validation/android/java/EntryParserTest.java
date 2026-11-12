import co.ostorlab.rasp.entry.EntryPointValidation;
/** Shared independent C/Java tuples. MATCH never means caller authorization. */
public final class EntryParserTest {
    public static void main(String[] args) throws Exception {
        EntryPointValidation.Rule rule = new EntryPointValidation.Rule(1,1,1,1,0,"https","links.example.invalid","/open/help",
            "append_demo_receipt","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        EntryPointValidation.Binding binding = new EntryPointValidation.Binding(new EntryPointValidation.Rule[]{rule},new EntryPointValidation.CallerProfile[0]);
        EntryPointValidation.Check result = EntryPointValidation.classify(binding,"https://links.example.invalid/open/help",1,1);
        if(result.status!=0 || result.routeId!=1 || result.callerState!=0) throw new AssertionError("canonical Java route must match without caller authority");
        int count=0;
        for(String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[0]))) {
            if(line.startsWith("#")) continue;
            String[] columns=line.split("\t");
            String url=null;
            if(!columns[4].equals("-")) {
                byte[] bytes=columns[4].equals("_") ? new byte[0] : java.util.HexFormat.of().parseHex(columns[4]);
                url=new String(bytes,java.nio.charset.StandardCharsets.UTF_8);
            }
            result=EntryPointValidation.classify(binding,url,Integer.parseInt(columns[0]),Integer.parseInt(columns[1]));
            if(result.status!=Integer.parseInt(columns[2]) || result.routeId!=Integer.parseInt(columns[3]) || result.callerState!=0)
                throw new AssertionError("shared vector "+count);
            count++;
        }
        if(count<40) throw new AssertionError("empty vectors");
        EntryPointValidation.Rule[] largest=new EntryPointValidation.Rule[16];
        String host="a".repeat(63)+"."+"a".repeat(63)+"."+"a".repeat(63)+"."+"a".repeat(61);
        String path=("/"+"a".repeat(63)).repeat(4);
        for(int index=0;index<16;index++) largest[index]=new EntryPointValidation.Rule(index+1,1,1,1,0,
            "app."+"a".repeat(28),host,path.substring(0,255)+(char)('A'+index),"a".repeat(32),"a".repeat(64));
        EntryPointValidation.CallerProfile[] profiles=new EntryPointValidation.CallerProfile[4];
        for(int index=0;index<4;index++) profiles[index]=new EntryPointValidation.CallerProfile("p".repeat(255),"q".repeat(255),new byte[][]{new byte[32],new byte[32]});
        if(new EntryPointValidation.Binding(largest,profiles).valid) throw new AssertionError("aggregate configuration exceeds 24KiB");
        if(!new EntryPointValidation.Binding(java.util.Arrays.copyOf(largest,15),profiles).valid) throw new AssertionError("bounded configuration refused");
        System.out.println("PASS Java shared classifier vectors: "+count);
    }
}
