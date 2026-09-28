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
    // Native access is used only by the explicit file/directory fsync helper.
    jvmArgs("--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny")
    inputs.dir(snapshot)
    systemProperty("totipo.test.snapshot", snapshot.asFile.absolutePath)
    // Backend durability tests use the checkout's filesystem, not a potentially tmpfs /tmp.
    // Other tests keep short default paths (in particular Unix-domain socket fixtures).
    systemProperty("totipo.test.local-storage-directory", layout.buildDirectory.dir("test-storage").get().asFile.absolutePath)
}
