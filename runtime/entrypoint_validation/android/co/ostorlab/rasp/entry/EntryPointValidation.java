package co.ostorlab.rasp.entry;

import android.app.Activity;
import android.content.ContentProvider;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Looper;
import android.os.Process;
import android.os.UserHandle;
import java.util.Set;

/** Host-source validation only. MATCH is classification, never an effect permit or backend authority. */
public final class EntryPointValidation {
    private EntryPointValidation() {}
    public static final int MATCH=0, REJECTED=1, UNAVAILABLE=2, UNSUPPORTED=3, NEEDS_HOST_FLOW=4;
    public static final int ANDROID_LINK=1, ANDROID_BINDER=2, ANDROID_PROVIDER_QUERY=3, IOS_CUSTOM_URL=4, IOS_WEB_ACTIVITY=5;
    public static final int OPEN=1, QUERY_STATUS=2, DEMO_CALL=3;
    public static final int PUBLIC_NAVIGATION=1, CALLER_RESTRICTED_NONSENSITIVE=2, CONFIRMATION_ENTRY=3, REPLAY_SENSITIVE_REJECT=4;

    /** Immutable app-compiled rule. The Binding rejects the entire table on malformed/duplicate rules. */
    public static final class Rule {
        public final int routeId, delivery, method, dispatchClass, callerProfile;
        public final String scheme, authority, path, operation, expectedPolicySha256;
        public Rule(int routeId,int delivery,int method,int dispatchClass,int callerProfile,
                    String scheme,String authority,String path,String operation,String expectedPolicySha256) {
            this.routeId=routeId; this.delivery=delivery; this.method=method; this.dispatchClass=dispatchClass;
            this.callerProfile=callerProfile; this.scheme=scheme; this.authority=authority; this.path=path;
            this.operation=operation; this.expectedPolicySha256=expectedPolicySha256;
        }
    }
    /** Reviewed signing-history pins and a signature permission declared by this host. No dynamic enrollment. */
    public static final class CallerProfile {
        public final String packageName, permission;
        private final byte[][] pins;
        public CallerProfile(String packageName,String permission,byte[][] pins) {
            this.packageName=packageName; this.permission=permission;
            boolean valid=pins!=null && pins.length>=1 && pins.length<=2;
            if(valid) for(byte[] pin:pins) if(pin==null || pin.length!=32) valid=false;
            this.pins=valid ? new byte[pins.length][] : new byte[0][];
            if(valid) for(int index=0;index<pins.length;index++) this.pins[index]=pins[index].clone();
        }
    }
    /** Immutable <=16-rule/4-profile binding; no host objects, input history or permission cache retained. */
    public static final class Binding {
        private final Rule[] rules;
        private final CallerProfile[] profiles;
        public final boolean valid;
        public Binding(Rule[] rules,CallerProfile[] profiles) {
            boolean good=rules!=null && rules.length>=1 && rules.length<=16 && profiles!=null && profiles.length<=4;
            if(good) {
                for(CallerProfile profile:profiles) if(profile==null || !ascii(profile.packageName,1,255)
                    || !ascii(profile.permission,1,255) || profile.pins.length==0) good=false;
                for(int index=0;index<rules.length;index++) {
                    Rule rule=rules[index];
                    if(!validRule(rule) || rule.callerProfile>profiles.length) { good=false; continue; }
                    for(int prior=0;prior<index;prior++) {
                        Rule other=rules[prior];
                        if(other!=null && (other.routeId==rule.routeId || (other.delivery==rule.delivery && other.method==rule.method
                            && same(other.scheme,rule.scheme) && same(other.authority,rule.authority) && same(other.path,rule.path)))) good=false;
                    }
                }
            }
            // Bounded UTF16 payload plus conservative primitive/terminator storage, excluding VM object overhead.
            // Counts are checked before this pass (<=16 rules, <=4 profiles, <=2 pins); long arithmetic cannot wrap.
            long payload=0;
            if(good) {
                for(Rule rule:rules) payload+=32L+2L*(rule.scheme.length()+rule.authority.length()+rule.path.length()
                    +rule.operation.length()+rule.expectedPolicySha256.length()+5L);
                for(CallerProfile profile:profiles) payload+=16L+2L*(profile.packageName.length()+profile.permission.length()+2L)
                    +32L*profile.pins.length;
                if(payload>24L*1024L) good=false;
            }
            valid=good;
            this.rules=good ? rules.clone() : new Rule[0];
            this.profiles=good ? profiles.clone() : new CallerProfile[0];
        }
        /** App-compiled route lookup only; a returned rule is not an authorization result. */
        public Rule rule(int routeId) {
            for(Rule rule:rules) if(rule.routeId==routeId) return rule;
            return null;
        }
    }
    /** Owned finite diagnostics. No URL, caller identity or native decision is retained. */
    public static final class Check {
        public final int version=1, size=32, status, reason, routeId, delivery, method, callerState;
        private Check(int status,int reason,int routeId,int delivery,int method,int callerState) {
            this.status=status; this.reason=reason; this.routeId=routeId; this.delivery=delivery;
            this.method=method; this.callerState=callerState;
        }
    }
    private static boolean same(String left,String right) { return left!=null && left.equals(right); }
    private static Check failure(int status,int reason,int delivery,int method) {
        return new Check(status,reason,0,delivery>=1 && delivery<=5 ? delivery : 0,method>=1 && method<=3 ? method : 0,0);
    }
    private static boolean lower(char value) { return value>='a' && value<='z'; }
    private static boolean digit(char value) { return value>='0' && value<='9'; }
    private static boolean ascii(String value,int minimum,int maximum) {
        if(value==null || value.length()<minimum || value.length()>maximum) return false;
        for(int index=0;index<value.length();index++) if(value.charAt(index)<=32 || value.charAt(index)>=127) return false;
        return true;
    }
    private static boolean scheme(String value,int delivery) {
        if(!ascii(value,1,32) || !lower(value.charAt(0))) return false;
        for(int index=1;index<value.length();index++) {
            char c=value.charAt(index); if(!lower(c) && !digit(c) && c!='.' && c!='-') return false;
        }
        boolean custom=value.length()>4 && value.startsWith("app.");
        return delivery==ANDROID_LINK ? value.equals("https") || custom : delivery==IOS_CUSTOM_URL ? custom :
            delivery==IOS_WEB_ACTIVITY ? value.equals("https") : delivery==ANDROID_PROVIDER_QUERY && value.equals("content");
    }
    private static boolean authority(String value) {
        if(!ascii(value,1,253)) return false;
        int begin=0, labels=0;
        for(int index=0;index<=value.length();index++) {
            if(index!=value.length() && value.charAt(index)!='.') {
                char c=value.charAt(index); if(!lower(c) && !digit(c) && c!='-') return false;
                continue;
            }
            int count=index-begin;
            if(count==0 || count>63 || value.charAt(begin)=='-' || value.charAt(index-1)=='-'
                || (count>=4 && value.startsWith("xn--",begin))) return false;
            labels++;
            if(index==value.length()) {
                if(count<2) return false;
                for(int tail=begin;tail<index;tail++) if(!lower(value.charAt(tail))) return false;
            }
            begin=index+1;
        }
        return labels>=2;
    }
    private static boolean path(String value) {
        if(!ascii(value,1,256) || value.charAt(0)!='/') return false;
        if(value.length()==1) return true;
        int begin=1, segments=0;
        for(int index=1;index<=value.length();index++) {
            if(index!=value.length() && value.charAt(index)!='/') {
                char c=value.charAt(index);
                if(!lower(c) && !digit(c) && !(c>='A' && c<='Z') && c!='.' && c!='_' && c!='~' && c!='-') return false;
                continue;
            }
            int count=index-begin;
            if(count==0 || count>64 || (count==1 && value.charAt(begin)=='.') ||
                (count==2 && value.charAt(begin)=='.' && value.charAt(begin+1)=='.') || ++segments>16) return false;
            begin=index+1;
        }
        return true;
    }
    private static boolean validRule(Rule rule) {
        if(rule==null || rule.routeId<1 || rule.routeId>16 || rule.delivery<1 || rule.delivery>5 ||
            rule.method!=(rule.delivery==2 ? 3 : rule.delivery==3 ? 2 : 1) || rule.dispatchClass<1 || rule.dispatchClass>4 ||
            rule.callerProfile<0 || rule.callerProfile>4 || (rule.dispatchClass==2 ? rule.callerProfile==0 : rule.callerProfile!=0) ||
            ((rule.delivery==2 || rule.delivery==3) && rule.dispatchClass!=2 && rule.dispatchClass!=4) ||
            !ascii(rule.operation,1,32) || !ascii(rule.expectedPolicySha256,64,64)) return false;
        for(int index=0;index<rule.operation.length();index++) {
            char c=rule.operation.charAt(index);
            if(!lower(c) && !digit(c) && !(c>='A' && c<='Z') && c!='_' && c!='.' && c!='-') return false;
        }
        for(int index=0;index<64;index++) {
            char c=rule.expectedPolicySha256.charAt(index); if(!digit(c) && !(c>='a' && c<='f')) return false;
        }
        return rule.delivery==2 ? same(rule.scheme,"") && same(rule.authority,"") && same(rule.path,"") :
            scheme(rule.scheme,rule.delivery) && authority(rule.authority) && path(rule.path);
    }
    /** Pure borrowed-string classifier. No decoding, network, identity or gate call. */
    public static Check classify(Binding binding,String url,int delivery,int method) {
        if(binding==null || !binding.valid) return failure(REJECTED,2,delivery,method);
        if(delivery<1 || delivery>5 || method<1 || method>3) return failure(REJECTED,1,delivery,method);
        if(method!=(delivery==2 ? 3 : delivery==3 ? 2 : 1)) return failure(REJECTED,9,delivery,method);
        if(delivery==2) {
            if(url!=null) return failure(REJECTED,1,delivery,method);
            for(Rule rule:binding.rules) if(rule.delivery==delivery && rule.method==method) return new Check(MATCH,0,rule.routeId,delivery,method,0);
            return failure(REJECTED,8,delivery,method);
        }
        if(url==null || url.length()==0) return failure(REJECTED,1,delivery,method);
        if(url.length()>1024) return failure(REJECTED,3,delivery,method);
        for(int index=0;index<url.length();index++) {
            char c=url.charAt(index);
            if(c<=32 || c>=127 || c=='\\' || c=='+' || c=='%') return failure(REJECTED,4,delivery,method);
            if(c=='?' || c=='#') return failure(REJECTED,7,delivery,method);
        }
        int colon=url.indexOf(':');
        if(colon<1 || colon>32 || colon+3>=url.length() || url.charAt(colon+1)!='/' || url.charAt(colon+2)!='/') return failure(REJECTED,4,delivery,method);
        String scheme=url.substring(0,colon);
        if(!scheme(scheme,delivery)) return failure(REJECTED,4,delivery,method);
        int slash=url.indexOf('/',colon+3);
        if(slash<0) return failure(REJECTED,6,delivery,method);
        String authority=url.substring(colon+3,slash), path=url.substring(slash);
        if(!authority(authority)) return failure(REJECTED,5,delivery,method);
        if(!path(path)) return failure(REJECTED,6,delivery,method);
        for(Rule rule:binding.rules) if(rule.delivery==delivery && rule.method==method && rule.scheme.equals(scheme)
            && rule.authority.equals(authority) && rule.path.equals(path)) return new Check(MATCH,0,rule.routeId,delivery,method,0);
        return failure(REJECTED,8,delivery,method);
    }
    private static boolean mainThread() { return Looper.myLooper()==Looper.getMainLooper(); }
    /** Check only the callback's current Intent envelope. Extras are never touched or forwarded. */
    private static Check intent(Activity host,Intent intent,Binding binding) {
        if(!mainThread()) return failure(UNAVAILABLE,15,1,1);
        if(host==null || intent==null) return failure(REJECTED,10,1,1);
        if(!ascii(intent.getAction(),1,128) || !Intent.ACTION_VIEW.equals(intent.getAction()) || intent.getData()==null ||
            intent.getType()!=null || intent.getSelector()!=null || intent.getClipData()!=null ||
            (intent.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION))!=0 ||
            (intent.getPackage()!=null && !intent.getPackage().equals(host.getPackageName())) ||
            (intent.getComponent()!=null && !intent.getComponent().equals(host.getComponentName()))) return failure(REJECTED,10,1,1);
        Set<String> categories=intent.getCategories();
        if(categories!=null) {
            if(categories.size()>2) return failure(REJECTED,10,1,1);
            for(String category:categories) if(!Intent.CATEGORY_DEFAULT.equals(category) && !Intent.CATEGORY_BROWSABLE.equals(category)) return failure(REJECTED,10,1,1);
        }
        return classify(binding,intent.getData().toString(),1,1);
    }
    private static Check disposition(Binding binding,Check check) {
        if(check.status!=MATCH) return check;
        Rule rule=binding.rule(check.routeId);
        return rule.dispatchClass==REPLAY_SENSITIVE_REJECT ? failure(NEEDS_HOST_FLOW,19,check.delivery,check.method) : check;
    }
    /** Initial launch only. API31..34 cannot authorize a restricted Activity route. */
    public static Check checkInitialActivity(Activity host,Intent intent,Binding binding) {
        return activity(host,intent,binding,false);
    }
    /** Invoke only inside onNewIntent with that callback Intent, before posting or replacing it. */
    public static Check checkNewActivity(Activity host,Intent intent,Binding binding) {
        return activity(host,intent,binding,true);
    }
    private static Check activity(Activity host,Intent input,Binding binding,boolean newIntent) {
        try {
            Check check=disposition(binding,intent(host,input,binding));
            if(check.status!=MATCH) return check;
            Rule rule=binding.rule(check.routeId);
            if(rule.callerProfile==0) return new Check(MATCH,0,check.routeId,1,1,3);
            if(Build.VERSION.SDK_INT<35) return failure(UNSUPPORTED,11,1,1);
            return Api35.check(host,binding,check,newIntent);
        } catch(PackageManager.NameNotFoundException | RuntimeException | LinkageError error) { return failure(UNAVAILABLE,14,1,1); }
    }
    /** Newer platform types stay in a lazily resolved class, never API31 signatures. */
    private static final class Api35 {
        static Check check(Activity host,Binding binding,Check check,boolean newIntent) throws PackageManager.NameNotFoundException {
            android.app.ComponentCaller caller=newIntent ? host.getCurrentCaller() : host.getCaller();
            if(caller==null) return failure(UNAVAILABLE,11,1,1);
            return caller(host,binding,check,caller.getUid(),caller.getPackage(),false);
        }
    }
    /** Check live synchronous Binder identity at the actual method boundary. No own-process fallback. */
    public static Check checkBinder(Context host,Binding binding) {
        try {
            int uid=Binder.getCallingUidOrThrow();
            Check check=disposition(binding,classify(binding,null,2,3));
            return check.status==MATCH ? caller(host,binding,check,uid,null,true) : check;
        } catch(PackageManager.NameNotFoundException | RuntimeException | LinkageError error) { return failure(UNAVAILABLE,14,2,3); }
    }
    /** Query invocation only; never use getCallingPackageUnchecked or carry this result to a worker. */
    public static Check checkProviderQuery(ContentProvider host,Uri uri,Binding binding) {
        try {
            int uid=Binder.getCallingUidOrThrow();
            if(host==null || uri==null) return failure(REJECTED,1,3,2);
            Check check=disposition(binding,classify(binding,uri.toString(),3,2));
            if(check.status!=MATCH) return check;
            String packageName=host.getCallingPackage();
            return packageName==null ? failure(UNAVAILABLE,11,3,2) : caller(host.getContext(),binding,check,uid,packageName,true);
        } catch(PackageManager.NameNotFoundException | RuntimeException | LinkageError error) { return failure(UNAVAILABLE,14,3,2); }
    }
    /** Resolve every identity, permission and signing-history pin afresh; never export/cache the UID. */
    private static Check caller(Context host,Binding binding,Check check,int uid,String packageName,boolean transaction) throws PackageManager.NameNotFoundException {
        if(host==null || uid<0 || packageName==null && !transaction) return failure(UNAVAILABLE,11,check.delivery,check.method);
        if(uid==Process.myUid() || !Process.isApplicationUid(uid) || !UserHandle.getUserHandleForUid(uid).equals(Process.myUserHandle()))
            return failure(REJECTED,12,check.delivery,check.method);
        Rule rule=binding.rule(check.routeId);
        if(rule.callerProfile<1 || rule.callerProfile>binding.profiles.length) return failure(REJECTED,2,check.delivery,check.method);
        CallerProfile profile=binding.profiles[rule.callerProfile-1];
        PackageManager pm=host.getPackageManager();
        if(pm==null || host.getApplicationInfo().uid!=Process.myUid()) return failure(UNAVAILABLE,14,check.delivery,check.method);
        String[] packages=pm.getPackagesForUid(uid);
        if(packages==null || packages.length!=1 || !profile.packageName.equals(packages[0]) ||
            (packageName!=null && !profile.packageName.equals(packageName))) return failure(REJECTED,12,check.delivery,check.method);
        ApplicationInfo app=pm.getApplicationInfo(profile.packageName,0);
        if(app==null || app.uid!=uid) return failure(REJECTED,12,check.delivery,check.method);
        PermissionInfo permission=pm.getPermissionInfo(profile.permission,0);
        if(permission==null || permission.getProtection()!=PermissionInfo.PROTECTION_SIGNATURE ||
            permission.getProtectionFlags()!=0 || !host.getPackageName().equals(permission.packageName)) return failure(REJECTED,13,check.delivery,check.method);
        int granted=transaction ? host.checkCallingPermission(profile.permission) : host.checkPermission(profile.permission,-1,uid);
        if(granted!=PackageManager.PERMISSION_GRANTED) return failure(REJECTED,13,check.delivery,check.method);
        for(byte[] pin:profile.pins) if(pm.hasSigningCertificate(profile.packageName,pin,PackageManager.CERT_INPUT_SHA256))
            return new Check(MATCH,0,check.routeId,check.delivery,check.method,2);
        return failure(REJECTED,12,check.delivery,check.method);
    }
}
