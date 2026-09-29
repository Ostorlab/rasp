package dev.ostorlab.rasp;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;
import java.util.Set;
import java.util.stream.Stream;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Seeded constant masking and integer-return integrity weaving before JAR/D8 packaging. */
public abstract class HardenClasses extends DefaultTask {
    @InputFiles @PathSensitive(PathSensitivity.RELATIVE) public abstract ConfigurableFileCollection getClasses();
    @OutputDirectory public abstract DirectoryProperty getDestination();
    @Input public abstract Property<Long> getSeed();
    @Input public abstract ListProperty<String> getMethods();
    @Input public abstract Property<String> getProbeOwner();
    @Input public abstract ListProperty<String> getRenameMethods();
    @OutputFile public abstract RegularFileProperty getSymbolsMap();

    private static int mask(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return ((bytes[0] & 255) << 24 | (bytes[1] & 255) << 16 | (bytes[2] & 255) << 8 | bytes[3] & 255) | 1;
        } catch (NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
    }

    private byte[] transform(byte[] bytes, Set<String> missing, Map<String, String> renames) {
        ClassReader reader = new ClassReader(bytes);
        String owner = reader.getClassName();
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
            @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                String selection = owner + "#" + name + descriptor;
                MethodVisitor original = super.visitMethod(access, renames.getOrDefault(selection, name), descriptor, signature, exceptions);
                MethodVisitor target = new MethodVisitor(Opcodes.ASM9, original) {
                    @Override public void visitMethodInsn(int opcode, String callOwner, String callName, String callDescriptor, boolean isInterface) {
                        super.visitMethodInsn(opcode, callOwner, renames.getOrDefault(callOwner + "#" + callName + callDescriptor, callName), callDescriptor, isInterface);
                    }
                    @Override public void visitLdcInsn(Object value) { super.visitLdcInsn(renameConstant(value, renames)); }
                    @Override public void visitInvokeDynamicInsn(String callName, String callDescriptor, Handle bootstrap, Object... arguments) {
                        Object[] rewritten = new Object[arguments.length];
                        for (int i = 0; i < arguments.length; i++) rewritten[i] = renameConstant(arguments[i], renames);
                        super.visitInvokeDynamicInsn(callName, callDescriptor, (Handle)renameConstant(bootstrap, renames), rewritten);
                    }
                };
                if (!getMethods().get().contains(selection)) return target;
                if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0 || Type.getReturnType(descriptor).getSort() != Type.INT)
                    throw new IllegalArgumentException("Selected method must have bytecode and return int: " + selection);
                if (owner.equals(getProbeOwner().get()) && name.equals("probe")) throw new IllegalArgumentException("Cannot weave probe itself");
                missing.remove(selection);
                return new MethodVisitor(Opcodes.ASM9, target) {
                    int counter;
                    private void constant(int value) {
                        int key = mask(getSeed().get() + ":" + selection + ":" + counter++);
                        super.visitLdcInsn(value ^ key);
                        super.visitLdcInsn(key);
                        super.visitInsn(Opcodes.IXOR);
                    }
                    @Override public void visitInsn(int opcode) {
                        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) { constant(opcode - Opcodes.ICONST_0); return; }
                        if (opcode == Opcodes.IRETURN) {
                            super.visitLdcInsn(mask(getSeed().get() + ":" + selection));
                            super.visitMethodInsn(Opcodes.INVOKESTATIC, getProbeOwner().get(), "probe", "(I)I", false);
                            super.visitInsn(Opcodes.IXOR);
                        }
                        super.visitInsn(opcode);
                    }
                    @Override public void visitIntInsn(int opcode, int operand) {
                        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) constant(operand);
                        else super.visitIntInsn(opcode, operand);
                    }
                    @Override public void visitLdcInsn(Object value) {
                        if (value instanceof Integer) constant((Integer)value);
                        else super.visitLdcInsn(value);
                    }
                };
            }
        };
        reader.accept(visitor, 0);
        return writer.toByteArray();
    }

    private static Object renameConstant(Object value, Map<String, String> renames) {
        if (value instanceof Handle) {
            Handle handle = (Handle)value;
            String name = renames.getOrDefault(handle.getOwner() + "#" + handle.getName() + handle.getDesc(), handle.getName());
            return new Handle(handle.getTag(), handle.getOwner(), name, handle.getDesc(), handle.isInterface());
        }
        if (value instanceof ConstantDynamic) {
            ConstantDynamic dynamic = (ConstantDynamic)value;
            Object[] arguments = new Object[dynamic.getBootstrapMethodArgumentCount()];
            for (int i = 0; i < arguments.length; i++) arguments[i] = renameConstant(dynamic.getBootstrapMethodArgument(i), renames);
            return new ConstantDynamic(dynamic.getName(), dynamic.getDescriptor(), (Handle)renameConstant(dynamic.getBootstrapMethod(), renames), arguments);
        }
        return value;
    }

    private Map<String, String> findRenames() throws IOException {
        Map<String, String> renames = new TreeMap<>();
        Set<String> existing = new HashSet<>();
        Set<String> requested = new HashSet<>(getRenameMethods().get());
        if (requested.size() != getRenameMethods().get().size()) throw new IllegalArgumentException("Duplicate rename selection");
        for (File directory : getClasses().getFiles()) {
            if (!directory.exists()) continue;
            try (Stream<Path> files = Files.walk(directory.toPath())) {
                for (Path path : (Iterable<Path>) files.filter(file -> file.toString().endsWith(".class")).sorted()::iterator) {
                    ClassReader reader = new ClassReader(Files.readAllBytes(path));
                    String owner = reader.getClassName();
                    reader.accept(new ClassVisitor(Opcodes.ASM9) {
                        @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                            String selection = owner + "#" + name + descriptor;
                            existing.add(selection);
                            if (requested.contains(selection)) {
                                if ((access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) != (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC) ||
                                    (access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0 || name.startsWith("<"))
                                    throw new IllegalArgumentException("Rename selection must be private static managed bytecode: " + selection);
                                renames.put(selection, "r" + Integer.toUnsignedString(mask(getSeed().get() + ":rename:" + selection), 16));
                            }
                            return null;
                        }
                    }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                }
            }
        }
        requested.removeAll(renames.keySet());
        if (!requested.isEmpty()) throw new IllegalArgumentException("Rename methods not found: " + requested);
        Set<String> targets = new HashSet<>();
        for (Map.Entry<String, String> entry : renames.entrySet()) {
            String original = entry.getKey();
            String target = original.substring(0, original.indexOf('#') + 1) + entry.getValue() + original.substring(original.indexOf('('));
            if (existing.contains(target) || !targets.add(target)) throw new IllegalArgumentException("Rename collision: " + target);
        }
        return renames;
    }

    @TaskAction public void harden() throws IOException {
        if (getMethods().get().isEmpty()) throw new IllegalArgumentException("At least one selected method is required");
        Map<String, String> renames = findRenames();
        Set<String> missing = new HashSet<>(getMethods().get());
        if (missing.size() != getMethods().get().size()) throw new IllegalArgumentException("Duplicate selected methods");
        Path output = getDestination().get().getAsFile().toPath();
        getProject().delete(output.toFile());
        Set<Path> written = new HashSet<>();
        for (File directory : getClasses().getFiles()) {
            Path root = directory.toPath();
            if (!Files.exists(root)) continue;
            try (Stream<Path> files = Files.walk(root)) {
                for (Path path : (Iterable<Path>) files.filter(Files::isRegularFile).sorted()::iterator) {
                    Path relative = root.relativize(path);
                    if (!written.add(relative)) throw new IllegalArgumentException("Duplicate class output: " + relative);
                    Path destination = output.resolve(relative);
                    Files.createDirectories(destination.getParent());
                    byte[] bytes = Files.readAllBytes(path);
                    Files.write(destination, path.toString().endsWith(".class") ? transform(bytes, missing, renames) : bytes);
                }
            }
        }
        if (!missing.isEmpty()) throw new IllegalArgumentException("Selected methods not found: " + missing);
        Path map = getSymbolsMap().get().getAsFile().toPath();
        Files.createDirectories(map.getParent());
        StringBuilder mapping = new StringBuilder();
        renames.forEach((original, renamed) -> mapping.append(original).append('\t').append(renamed).append('\n'));
        Files.write(map, mapping.toString().getBytes(StandardCharsets.UTF_8));
    }
}
