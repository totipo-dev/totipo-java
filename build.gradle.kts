import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.api.tasks.wrapper.Wrapper
import org.gradle.external.javadoc.JavadocMemberLevel
import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    base
}

description = "Totipo Java libraries"

subprojects {
    apply(plugin = "java-library")
    group = "dev.totipo"

    extensions.configure<JavaPluginExtension> {
        toolchain.languageVersion.set(JavaLanguageVersion.of(25))
        withSourcesJar()
        withJavadocJar()
    }
    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }
    tasks.withType<Javadoc>().configureEach {
        options.encoding = "UTF-8"
        // The implementation still intentionally keeps most APIs package-private.
        (options as StandardJavadocDocletOptions).memberLevel = JavadocMemberLevel.PACKAGE
    }
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
    dependencyLocking {
        lockAllConfigurations()
    }
}

tasks.named("build") { dependsOn(subprojects.map { "${it.path}:build" }) }
tasks.named("check") { dependsOn(subprojects.map { "${it.path}:check" }) }
tasks.named("assemble") { dependsOn(subprojects.map { "${it.path}:assemble" }) }
tasks.named("clean") { dependsOn(subprojects.map { "${it.path}:clean" }) }
tasks.register("test") { dependsOn(subprojects.map { "${it.path}:test" }) }

tasks.named<Wrapper>("wrapper") {
    gradleVersion = "9.8.0"
    distributionType = Wrapper.DistributionType.BIN
    distributionSha256Sum = "bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c"
}
