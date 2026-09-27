plugins {
    `java-library`
}

description = "Linux/JVM filesystem adapter for Totipo"
base.archivesName.set("totipo-fs-linux")

java.toolchain.languageVersion.set(JavaLanguageVersion.of(25))
tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
}

dependencies {
    api(project(":core"))
    // Live-file tests read four existing core-owned JSON fixtures directly.
    testImplementation(libs.jackson.core)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

val snapshot = rootProject.layout.projectDirectory.dir("core/src/test/resources/totipo-spec/v1-pre-rc")
tasks.test {
    inputs.dir(snapshot)
    systemProperty("totipo.test.snapshot", snapshot.asFile.absolutePath)
}
