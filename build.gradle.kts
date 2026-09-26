import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.api.tasks.wrapper.Wrapper

plugins {
    `java-library`
}

group = "dev.totipo"
description = "Java library for Totipo vault repositories"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    // Build with JDK 21, but keep the reusable library compatible with Java 17.
    options.release.set(17)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.withType<Javadoc>().configureEach {
    options.encoding = "UTF-8"
}

dependencies {
    // M0 intentionally has no production dependencies.
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

dependencyLocking {
    lockAllConfigurations()
}

tasks.named<Wrapper>("wrapper") {
    gradleVersion = "9.8.0"
    distributionType = Wrapper.DistributionType.BIN
    distributionSha256Sum = "bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c"
}
