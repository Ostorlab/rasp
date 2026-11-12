package fixture.entrypoints;
import co.ostorlab.rasp.entry.EntryPointValidation;
/** Compiled argument-free demo actions. Certificate pins are public placeholders, never keys. */
public final class Routes {
    private Routes() {}
    public static final String HASH="5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81";
    public static final String PERMISSION="fixture.entrypoints.CALL_DEMO";
    public static final String OPERATION="append_demo_receipt";
    private static EntryPointValidation.Rule rule(int route,int delivery,int method,int effect,int profile,String scheme,String path) {
        return new EntryPointValidation.Rule(route,delivery,method,effect,profile,scheme,
            delivery==2 ? "" : delivery==3 ? "fixture.entrypoints.status" : "links.example.invalid",path,OPERATION,HASH);
    }
    private static EntryPointValidation.CallerProfile[] profiles() {
        return new EntryPointValidation.CallerProfile[]{new EntryPointValidation.CallerProfile("fixture.entrycaller",PERMISSION,new byte[][]{new byte[32]})};
    }
    public static final EntryPointValidation.Binding LINKS=new EntryPointValidation.Binding(new EntryPointValidation.Rule[]{
        rule(1,1,1,1,0,"https","/open/help"), rule(2,1,1,3,0,"https","/open/confirm"),
        rule(3,1,1,4,0,"https","/commit"), rule(4,1,1,2,1,"https","/partner/help"),
        rule(5,1,1,1,0,"app.raspdemo","/open/help")},profiles());
    public static final EntryPointValidation.Binding BINDER=new EntryPointValidation.Binding(new EntryPointValidation.Rule[]{rule(6,2,3,2,1,"","")},profiles());
    public static final EntryPointValidation.Binding PROVIDER=new EntryPointValidation.Binding(new EntryPointValidation.Rule[]{rule(7,3,2,2,1,"content","/status")},profiles());
}
