import java.io.DataInputStream

plugins {
    `java-library`
}

description = "Portable Totipo protocol, state, and discovery semantics"
base.archivesName.set("totipo-core")

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

dependencies {
    // BC is used only for lightweight Argon2id; existing crypto stays on JDK providers.
    implementation(libs.bcprov)
    testImplementation(libs.jackson.core)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// Inspect every production class, so an accidental target increase fails `check`.
val mainClasses = sourceSets.main.map { it.output.classesDirs }
val verifyJava17Bytecode = tasks.register("verifyJava17Bytecode") {
    group = "verification"
    description = "Verify all core production classes use Java 17 bytecode"
    dependsOn(tasks.compileJava)
    inputs.files(mainClasses)
    doLast {
        val classes = inputs.files.asFileTree.matching { include("**/*.class") }.files
        check(classes.isNotEmpty()) { "No core classes to verify" }
        classes.forEach { file ->
            DataInputStream(file.inputStream()).use { input ->
                check(input.readInt() == 0xCAFEBABE.toInt()) { "Invalid class: $file" }
                input.readUnsignedShort()
                check(input.readUnsignedShort() == 61) { "Not Java 17 bytecode: $file" }
            }
        }
    }
}
tasks.check { dependsOn(verifyJava17Bytecode) }
tasks.test { dependsOn(verifyJava17Bytecode) }
