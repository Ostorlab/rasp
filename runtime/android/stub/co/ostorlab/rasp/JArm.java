package co.ostorlab.rasp;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The Java arm of the key schedule: the interpreter of the per-app program the packer ships.
 *
 * <p>Each step of the program names a class and how many superclass hops to walk over it. This class resolves it
 * through the app's base class loader — through ART — and folds what the runtime reports into an HMAC-SHA256 chain
 * over the step's results, with the same RFC 5869 HKDF the native side derives through. The packer predicted the
 * chain's outcome on a real runtime and sealed the business dexes under it, so a runtime that resolves the steps
 * the way the packer predicted arms the store and the classes decrypt; anything else derives a different share,
 * the frames' tags fail, and nothing reports why.
 */
final class JArm {

    private static final int SHARE_LENGTH = 32;
    private static final int MAX_STEPS = 16;

    private JArm() {
    }

    /**
     * Runs the program the packer shipped and returns the share it yields on this runtime.
     *
     * @param base the app's base class loader, which holds the framework classes and the stub.
     * @param program the decrypted program, as the native side served it: a step count, then per step a kind, a
     *         hop count, and a class name.
     * @return the 32-byte share.
     * @throws IllegalArgumentException when the program is malformed.
     * @throws ClassNotFoundException when a step's class does not resolve; the caller then does not arm.
     */
    static byte[] run(ClassLoader base, byte[] program) throws ClassNotFoundException {
        int[] offset = new int[] {0};
        int count = readShort(program, offset);
        if (count < 1 || count > MAX_STEPS) {
            throw new IllegalArgumentException("bad step count");
        }
        byte[] state = new byte[SHARE_LENGTH];
        for (int step = 0; step < count; step++) {
            int kind = readByte(program, offset);
            int depth = readByte(program, offset);
            String name = readString(program, offset);
            byte[] input = observe(base, kind, depth, name);
            state = hkdf(state, input, info(step));
        }
        return state;
    }

    /**
     * Observes one step through the runtime: the resolved class's own name, or the names of the first {@code depth}
     * hops of its superclass chain, joined by NUL.
     *
     * @param base the app's base class loader.
     * @param kind the step's kind: 1 resolves, 2 walks the superclass chain.
     * @param depth the number of superclass hops to walk.
     * @param name the step's class name.
     * @return the bytes the step contributes to the chain.
     * @throws ClassNotFoundException when the class does not resolve.
     */
    private static byte[] observe(ClassLoader base, int kind, int depth, String name) throws ClassNotFoundException {
        if (kind == 1) {
            return base.loadClass(name).getName().getBytes(StandardCharsets.UTF_8);
        }
        if (kind != 2) {
            throw new IllegalArgumentException("bad step kind");
        }
        Class<?> current = base.loadClass(name);
        StringBuilder walk = new StringBuilder();
        for (int hop = 0; hop < depth; hop++) {
            current = current.getSuperclass();
            if (current == null) {
                throw new IllegalArgumentException("walk past the root class");
            }
            if (hop > 0) {
                walk.append('\0');
            }
            walk.append(current.getName());
        }
        return walk.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * One RFC 5869 HKDF-SHA256 step, 32 bytes of output: the chain state under the step's input.
     *
     * @param state the chain state, 32 bytes, the step's secret.
     * @param input the step's input, the HKDF salt.
     * @param info the step's info.
     * @return the next chain state.
     */
    private static byte[] hkdf(byte[] state, byte[] input, byte[] info) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(input, "HmacSHA256"));
            byte[] prk = mac.doFinal(state);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] block = new byte[info.length + 1];
            System.arraycopy(info, 0, block, 0, info.length);
            block[info.length] = 1;
            byte[] okm = mac.doFinal(block);
            byte[] out = new byte[SHARE_LENGTH];
            System.arraycopy(okm, 0, out, 0, SHARE_LENGTH);
            return out;
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * The info of step {@code index}'s HKDF step, assembled so the dex holds no whole literal of it.
     *
     * @param index the step's index in the chain.
     * @return the info bytes.
     */
    private static byte[] info(int index) {
        char[] head = {(char) ('q' + 1), 'a', 's', 'p', '.', 'v', '2', '.', 'j', '/'};
        String info = String.valueOf(head) + index;
        return info.getBytes(StandardCharsets.UTF_8);
    }

    private static int readByte(byte[] program, int[] offset) {
        if (offset[0] + 1 > program.length) {
            throw new IllegalArgumentException("truncated program");
        }
        return program[offset[0]++] & 0xFF;
    }

    private static int readShort(byte[] program, int[] offset) {
        if (offset[0] + 2 > program.length) {
            throw new IllegalArgumentException("truncated program");
        }
        int low = program[offset[0]++] & 0xFF;
        int high = program[offset[0]++] & 0xFF;
        return low | (high << 8);
    }

    private static String readString(byte[] program, int[] offset) {
        int length = readShort(program, offset);
        if (length < 1 || offset[0] + length > program.length) {
            throw new IllegalArgumentException("truncated program");
        }
        String name = new String(program, offset[0], length, StandardCharsets.UTF_8);
        offset[0] += length;
        return name;
    }
}
