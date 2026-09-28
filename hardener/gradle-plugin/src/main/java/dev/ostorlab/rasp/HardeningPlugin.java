package dev.ostorlab.rasp;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.api.tasks.bundling.Jar;

/** Produces an explicit hardenedJar artifact; the ordinary jar remains a development artifact. */
public final class HardeningPlugin implements Plugin<Project> {
    @Override public void apply(Project project) {
        project.getPlugins().apply("java");
        JavaPluginExtension java = project.getExtensions().getByType(JavaPluginExtension.class);
        SourceSet main = java.getSourceSets().getByName("main");
        TaskProvider<HardenClasses> transform = project.getTasks().register("hardenClasses", HardenClasses.class, task -> {
            task.dependsOn(project.getTasks().named("classes"));
            task.getClasses().from(main.getOutput().getClassesDirs());
            task.getDestination().convention(project.getLayout().getBuildDirectory().dir("rasp/classes"));
            task.getProbeOwner().convention("dev/ostorlab/rasp/Guard");
        });
        project.getTasks().register("hardenedJar", Jar.class, task -> {
            task.dependsOn(transform);
            task.getArchiveClassifier().set("hardened");
            task.from(transform.flatMap(HardenClasses::getDestination));
            task.from(main.getOutput().getResourcesDir());
            task.setPreserveFileTimestamps(false);
            task.setReproducibleFileOrder(true);
        });
    }
}
