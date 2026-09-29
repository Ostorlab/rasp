package dev.ostorlab.rasp;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Private build utility. Usage: PackClass key-file binary-class-name input.class output.raj */
public final class PackClass {
    private PackClass() {}
    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 4) throw new IllegalArgumentException("key-file identity input output required");
        byte[] key = Files.readAllBytes(Path.of(arguments[0]));
        byte[] plain = Files.readAllBytes(Path.of(arguments[2]));
        try {
            byte[] encrypted = AuthenticatedPackage.seal(plain, arguments[1], ignored -> key);
            Files.write(Path.of(arguments[3]), encrypted);
        } finally { Arrays.fill(key, (byte)0); Arrays.fill(plain, (byte)0); }
    }
}
