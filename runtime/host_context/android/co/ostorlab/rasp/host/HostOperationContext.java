package co.ostorlab.rasp.host;

import android.os.Looper;
import android.os.SystemClock;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.text.method.TransformationMethod;
import android.widget.EditText;
import co.ostorlab.rasp.RuntimeBridge;
import java.util.Arrays;

/** Optional host source, main-thread confined. No content reads, automatic observers or telemetry. */
public final class HostOperationContext {
    /** Immutable compiled equality expectation; never construct from runtime policyInfo. */
    public static final class Binding {
        public final String operation, expectedPolicySha256;
        public final boolean requireSecureInput;
        public Binding(String operation, String hash, boolean requireSecureInput) {
            if (!validText(operation, false) || !validText(hash, true)) throw new IllegalArgumentException("binding");
            this.operation = operation; this.expectedPolicySha256 = hash; this.requireSecureInput = requireSecureInput;
        }
    }
    /** Immutable finite event. Invalid enum/range values reach apply for attribution-aware rejection. */
    public static final class Event {
        public final int kind, purpose, secureEntry, lifecycle, attempt, completion;
        public final long generation, sequence;
        private final byte[] session, action;
        public Event(int kind, int purpose, int secureEntry, int lifecycle, int attempt, int completion,
                     long generation, long sequence, byte[] session, byte[] action) {
            if (session == null || action == null || session.length != 16 || action.length != 16)
                throw new IllegalArgumentException("opaque references must be exactly16 bytes");
            this.kind = kind; this.purpose = purpose; this.secureEntry = secureEntry; this.lifecycle = lifecycle;
            this.attempt = attempt; this.completion = completion; this.generation = generation; this.sequence = sequence;
            this.session = session.clone(); this.action = action.clone();
        }
        public byte[] sessionRef() { return session.clone(); }
        public byte[] actionRef() { return action.clone(); }
        private boolean same(Event other) {
            return other != null && kind == other.kind && purpose == other.purpose && secureEntry == other.secureEntry
                && lifecycle == other.lifecycle && attempt == other.attempt && completion == other.completion
                && generation == other.generation && sequence == other.sequence
                && Arrays.equals(session, other.session) && Arrays.equals(action, other.action);
        }
    }
    /** Owned version1/reason1 view; trust is always unverified host declaration0. */
    public static final class View {
        public final int version = 1, reasonVersion = 1, trust = 0;
        public final int status, reason, state, purpose, secureEntry, lifecycle, attempt;
        public final long generation, sequence, sessionAgeNs, actionAgeNs, lastEventAgeNs;
        public final boolean timingPresent, sequencePresent;
        private final byte[] session, action;
        private View(HostOperationContext owner, int status, int reason, boolean timing) {
            this.status = status; this.reason = reason; state = owner.state; purpose = owner.purpose;
            secureEntry = owner.secure; lifecycle = owner.lifecycle; attempt = owner.attempt;
            generation = owner.generation; sequence = owner.sequence; sequencePresent = sequence != 0;
            timingPresent = timing;
            sessionAgeNs = timing ? owner.lastTick - owner.sessionStart : 0;
            actionAgeNs = timing && owner.attempt != 0 ? owner.lastTick - owner.actionStart : 0;
            lastEventAgeNs = timing ? owner.lastTick - owner.eventTick : 0;
            boolean expose = status == 0 && (state == 1 || state == 2 || state == 9);
            session = expose ? owner.session.clone() : new byte[16];
            action = expose ? owner.action.clone() : new byte[16];
        }
        public byte[] sessionRef() { return session.clone(); }
        public byte[] actionRef() { return action.clone(); }
    }
    /** Actual native result, or null if no native call occurred/was available. Never a reusable permit. */
    public static final class GateResult {
        public final View context;
        public final RuntimeBridge.PolicyDecision nativeDecision;
        private GateResult(View context, RuntimeBridge.PolicyDecision decision) { this.context = context; nativeDecision = decision; }
    }

    private final Binding binding;
    private final byte[] session = new byte[16], action = new byte[16];
    private int state, purpose, secure, lifecycle, attempt, reason;
    private long generation, sequence, sessionStart, actionStart, eventTick, lastTick;
    private boolean hasClock, disposed;
    private Event last;

    public HostOperationContext(Binding binding) {
        if (!onMain()) throw new IllegalStateException("owner main thread required");
        if (binding == null) throw new IllegalArgumentException("binding");
        this.binding = binding;
    }
    private static boolean onMain() { return Looper.getMainLooper() != null && Looper.myLooper() == Looper.getMainLooper(); }
    private static boolean zero(byte[] value) { int all = 0; for (byte b : value) all |= b; return all == 0; }
    private static boolean validText(String text, boolean hash) {
        if (text == null || text.isEmpty() || text.length() > (hash ? 64 : 32) || (hash && text.length() != 64)) return false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (hash ? !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) :
                !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '-')) return false;
        }
        return true;
    }
    private View view(int status, int why, boolean timing) { return new View(this, status, why, timing); }
    private void closeFlow(int nextState, int why) {
        state = nextState; reason = why; purpose = 0; secure = 0; attempt = 0;
        Arrays.fill(session, (byte)0); Arrays.fill(action, (byte)0); last = null;
        sessionStart = 0; actionStart = 0; eventTick = 0;
    }
    private int sample(boolean starting) {
        final long now;
        try { now = SystemClock.elapsedRealtimeNanos(); }
        catch (RuntimeException | LinkageError error) { closeFlow(8, 9); return 9; }
        if (now < 0 || (hasClock && now < lastTick)) { closeFlow(8, 9); return 9; }
        lastTick = now; hasClock = true;
        if (starting) return 0;
        int why = now - sessionStart > 300000000000L ? 6 :
            attempt != 0 && now - actionStart > 120000000000L ? 7 : now - eventTick > 30000000000L ? 8 : 0;
        if (why != 0) { closeFlow(7, why); return 8; }
        return 0;
    }
    private static boolean canonical(Event e) {
        if (e.kind < 1 || e.kind > 8 || e.purpose < 0 || e.purpose > 6 || e.secureEntry < 0 || e.secureEntry > 4
            || e.lifecycle < 0 || e.lifecycle > 4 || e.generation <= 0 || e.sequence <= 0) return false;
        if (e.kind == 8) return zero(e.session) && zero(e.action) && e.attempt == 0 && e.purpose == 0
            && e.secureEntry == 0 && e.lifecycle == 0 && e.completion == 0;
        if (zero(e.session)) return false;
        if (e.kind == 1) return zero(e.action) && e.attempt == 0 && e.purpose == 0 && e.secureEntry == 0
            && e.completion == 0 && e.lifecycle == 1 && e.sequence == 1;
        if (e.kind == 4) return e.purpose == 0 && e.secureEntry == 0 && e.completion == 0
            && ((e.attempt == 0 && zero(e.action)) || (e.attempt >= 1 && e.attempt <= 3 && !zero(e.action)));
        if (e.attempt < 1 || e.attempt > 3 || zero(e.action) || e.lifecycle != 0) return false;
        if (e.kind == 2 || e.kind == 3 || e.kind == 7) return e.completion == 0;
        return e.purpose == 0 && e.secureEntry == 0 && (e.kind == 5 ? e.completion >= 1 && e.completion <= 2 : e.completion == 0);
    }
    private boolean attributable(Event e) {
        if (e.generation != generation || state == 0 || state == 6 || state == 7 || state == 8) return false;
        if (e.kind == 8) return zero(e.session) && zero(e.action);
        if (!Arrays.equals(e.session, session)) return false;
        if (e.kind == 3 || e.kind == 5 || e.kind == 6 || e.kind == 7)
            return Arrays.equals(e.action, action) && (e.attempt == attempt || (e.kind == 7 && e.attempt == attempt + 1));
        return true;
    }
    private boolean terminalRepeat(Event e) {
        return (state == 3 || state == 5) && last != null && e.kind == last.kind && e.generation == last.generation
            && e.sequence == last.sequence && e.attempt == last.attempt && e.completion == last.completion;
    }
    private boolean validTransition(Event e) {
        switch (e.kind) {
            case 2: return (state == 1 || state == 3 || state == 4 || state == 5) && e.attempt == 1
                && e.purpose != 0 && !Arrays.equals(e.action, action);
            case 3: return state == 2 && e.purpose == purpose;
            case 7: return (state == 9 || state == 4) && e.attempt == attempt + 1 && e.purpose == purpose;
            case 5: case 6: return state == 2 || state == 9;
            case 4: case 8: return true;
            default: return false;
        }
    }
    private boolean transition(Event e) {
        if (e.kind == 8) { closeFlow(6, 16); return true; }
        if (e.kind == 4) {
            if (state == 0 || state == 6 || state == 7 || state == 8) return false;
            lifecycle = e.lifecycle; if (lifecycle != 1) closeFlow(6, 3); return true;
        }
        if (e.kind == 2) {
            if ((state != 1 && state != 3 && state != 4 && state != 5) || e.attempt != 1 || e.purpose == 0
                || Arrays.equals(e.action, action)) return false;
            System.arraycopy(e.action, 0, action, 0, 16); actionStart = lastTick;
        } else if (e.kind == 3) {
            if (state != 2 || e.purpose != purpose) return false;
        } else if (e.kind == 7) {
            if ((state != 9 && state != 4) || e.attempt != attempt + 1 || e.purpose != purpose) return false;
        } else if (e.kind == 5 || e.kind == 6) {
            if (state != 2 && state != 9) return false;
            state = e.kind == 6 ? 5 : e.completion == 1 ? 3 : 4; secure = 0;
            if (state != 4 || e.attempt == 3) { Arrays.fill(action, (byte)0); purpose = 0; attempt = 0; actionStart = 0; }
            return true;
        } else return false;
        state = 2; purpose = e.purpose; secure = e.secureEntry; attempt = e.attempt; return true;
    }
    /** Apply canonical finite facts; old identities never refresh clocks or mutate a newer flow. */
    public View apply(Event e) {
        if (!onMain()) return unavailableView(4);
        if (disposed) return view(10, 1, false);
        if (e == null) return view(2, 12, false);
        if (!canonical(e)) { if (attributable(e)) closeFlow(8, 12); return view(2, 12, false); }
        if (e.kind == 1) {
            if (e.same(last)) return view(1, 0, false);
            if (generation == Long.MAX_VALUE) return view(11, 15, false);
            if (e.generation != generation + 1) {
                if (e.generation == generation && sequence == 1 && Arrays.equals(e.session, session)) closeFlow(8, 12);
                return view(5, 10, false);
            }
            if (!zero(session) && Arrays.equals(e.session, session)) return view(2, 12, false);
            if (sample(true) != 0) return view(9, 9, false);
            state = 1; lifecycle = 1; purpose = 0; secure = 0; attempt = 0; reason = 0;
            generation = e.generation; System.arraycopy(e.session, 0, session, 0, 16); Arrays.fill(action, (byte)0);
            sessionStart = lastTick; actionStart = 0;
        } else {
            if (e.generation != generation) return view(5, 10, false);
            if (terminalRepeat(e)) return view(1, 0, false);
            if (e.kind != 8 && !Arrays.equals(e.session, session)) return view(10, 10, false);
            if (e.same(last)) return view(1, 0, false);
            if (state == 0 || state == 6 || state == 7 || state == 8) return view(10, reason, false);
            if (e.kind != 2 && e.kind != 8 && (!Arrays.equals(e.action, action)
                || e.attempt != (e.kind == 7 ? attempt + 1 : attempt))) return view(7, 12, false);
            if (e.sequence < sequence) return view(6, 11, false);
            if (sequence == Long.MAX_VALUE || e.sequence != sequence + 1) { closeFlow(8, 11); return view(6, 11, false); }
            if (!validTransition(e)) { closeFlow(8, 12); return view(7, 12, false); }
            int clockStatus = sample(false); if (clockStatus != 0) return view(clockStatus, reason, false);
            if (!transition(e)) { closeFlow(8, 12); return view(7, 12, false); }
        }
        sequence = e.sequence; if (state != 6) eventTick = lastTick; last = e;
        if (state == 3 || state == 5 || (state == 4 && e.attempt == 3))
            last = new Event(e.kind, 0, 0, 0, e.attempt, e.completion, e.generation, e.sequence, new byte[16], new byte[16]);
        if (state == 6 && e.kind != 8) last = null;
        return view(0, reason, false);
    }
    /** Consume only after context admission; actual native failure never restores ACTIVE. */
    public GateResult gate(long expectedGeneration, long expectedSequence, int expectedAttempt) {
        if (!onMain()) return new GateResult(unavailableView(4), null);
        if (disposed) return new GateResult(view(10, 1, false), null);
        if (expectedGeneration <= 0 || expectedSequence <= 0 || expectedAttempt < 1 || expectedAttempt > 3)
            return new GateResult(view(2, 12, false), null);
        int mismatch = expectedGeneration != generation ? 10 : expectedSequence != sequence ? 11 : expectedAttempt != attempt ? 12 : 0;
        if (mismatch != 0) return new GateResult(view(10, mismatch, false), null);
        if (state != 2) return new GateResult(view(10, state == 9 ? 13 : reason, false), null);
        int clockStatus = sample(false); if (clockStatus != 0) return new GateResult(view(clockStatus, reason, false), null);
        int why = lifecycle != 1 ? 3 : purpose == 0 ? 4 : binding.requireSecureInput && (purpose > 2 || secure != 1) ? 5 : 0;
        if (why != 0) return new GateResult(view(10, why, true), null);
        state = 9;
        final RuntimeBridge.PolicyDecision decision;
        try { decision = RuntimeBridge.gateLocalOperation(binding.operation, binding.expectedPolicySha256); }
        catch (RuntimeException | LinkageError error) { return new GateResult(view(12, 14, true), null); }
        if (decision == null || decision.status() != RuntimeBridge.POLICY_OK || decision.action() < 0 || decision.action() > 2)
            return new GateResult(view(12, 14, true), decision);
        return new GateResult(view(0, 0, true), decision);
    }
    /** Wrong-thread output never reads mutable owner state. */
    private static View unavailableView(int status) {
        return new View(new HostOperationContext(), status, 1, false);
    }
    private HostOperationContext() { binding = null; }
    /** Stop logically clears SDK-owned facts; callers must release their own callbacks/copies. */
    public int close() {
        if (!onMain()) return 4;
        closeFlow(6, 16); state = 0; lifecycle = 0; reason = 0;
        generation = 0; sequence = 0; lastTick = 0; hasClock = false; disposed = true;
        return 0;
    }
    /** Sample only the explicitly supplied standard EditText's configuration, never its text/length/selection. */
    public static int secureEntry(Object selected) {
        if (!onMain() || selected == null) return 0;
        if (selected.getClass() != EditText.class) return 3;
        try {
            EditText field = (EditText)selected;
            int type = field.getInputType(), cls = type & InputType.TYPE_MASK_CLASS, variation = type & InputType.TYPE_MASK_VARIATION;
            TransformationMethod transform = field.getTransformationMethod();
            boolean password = (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
                || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD))
                || (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD);
            if (!password) return 2;
            if (transform == null) return 2;
            return transform.getClass() == PasswordTransformationMethod.class ? 1 : 0;
        } catch (RuntimeException | LinkageError error) { return 0; }
    }
}
