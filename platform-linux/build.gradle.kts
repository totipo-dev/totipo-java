import java.io.DataInputStream

plugins {
    `java-library`
}

description = "Linux durability and app-local custody for Totipo"
base.archivesName.set("totipo-platform-linux")

java.toolchain.languageVersion.set(JavaLanguageVersion.of(25))
tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
}

dependencies {
    api(project(":storage-nio"))
    testImplementation(testFixtures(project(":storage-nio")))
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

// Inspect every production class, so an accidental target increase fails `check`.
val mainClasses = sourceSets.main.map { it.output.classesDirs }
val verifyJava25Bytecode = tasks.register("verifyJava25Bytecode") {
    group = "verification"
    description = "Verify all platform-linux production classes use Java 25 bytecode"
    dependsOn(tasks.compileJava)
    inputs.files(mainClasses)
    doLast {
        val classes = inputs.files.asFileTree.matching { include("**/*.class") }.files
        check(classes.isNotEmpty()) { "No platform-linux classes to verify" }
        classes.forEach { file ->
            DataInputStream(file.inputStream()).use { input ->
                check(input.readInt() == 0xCAFEBABE.toInt()) { "Invalid class: $file" }
                check(input.readUnsignedShort() == 0) { "Preview bytecode: $file" }
                check(input.readUnsignedShort() == 69) { "Not Java 25 bytecode: $file" }
            }
        }
    }
}
tasks.check { dependsOn(verifyJava25Bytecode) }
tasks.test { dependsOn(verifyJava25Bytecode) }
