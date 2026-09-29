import java.io.DataInputStream

plugins {
    `java-library`
    `java-test-fixtures`
}

description = "Portable NIO configured-store filesystem implementation for Totipo"
base.archivesName.set("totipo-storage-nio")

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

dependencies {
    api(project(":core"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// Inspect every production class, so an accidental target increase fails `check`.
val mainClasses = sourceSets.main.map { it.output.classesDirs }
val verifyJava17Bytecode = tasks.register("verifyJava17Bytecode") {
    group = "verification"
    description = "Verify all storage-nio production classes use Java 17 bytecode"
    dependsOn(tasks.compileJava)
    inputs.files(mainClasses)
    doLast {
        val classes = inputs.files.asFileTree.matching { include("**/*.class") }.files
        check(classes.isNotEmpty()) { "No storage-nio classes to verify" }
        classes.forEach { file ->
            DataInputStream(file.inputStream()).use { input ->
                check(input.readInt() == 0xCAFEBABE.toInt()) { "Invalid class: $file" }
                check(input.readUnsignedShort() == 0) { "Preview bytecode: $file" }
                check(input.readUnsignedShort() == 61) { "Not Java 17 bytecode: $file" }
            }
        }
    }
}
tasks.check { dependsOn(verifyJava17Bytecode) }
tasks.test { dependsOn(verifyJava17Bytecode) }

val snapshot = rootProject.layout.projectDirectory.dir("core/src/test/resources/totipo-spec/v1-pre-rc")
tasks.test {
    inputs.dir(snapshot)
    systemProperty("totipo.test.snapshot", snapshot.asFile.absolutePath)
}
