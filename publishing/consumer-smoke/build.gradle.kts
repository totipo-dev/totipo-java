import org.gradle.api.artifacts.component.ModuleComponentIdentifier

plugins { java }
val releaseVersion = file("../../VERSION").readText().removeSuffix("\n")
java { toolchain.languageVersion.set(JavaLanguageVersion.of(25)) }
tasks.withType<JavaCompile>().configureEach { options.release.set(17) }
dependencies { implementation("dev.totipo:totipo-storage-nio:$releaseVersion") }
dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}
val compileArtifacts = configurations.compileClasspath
val runtimeArtifacts = configurations.runtimeClasspath
val verifyBoundary = tasks.register("verifyBoundary") {
    doLast {
        fun coordinates(configuration: Configuration): Set<String> =
            configuration.incoming.resolutionResult.allComponents.mapNotNull { component ->
                if (component.id == configuration.incoming.resolutionResult.rootComponent.get().id) null
                else {
                    check(component.id is ModuleComponentIdentifier) { "Source substitution: ${component.id}" }
                    (component.id as ModuleComponentIdentifier).let { "${it.group}:${it.module}:${it.version}" }
                }
            }.toSet()
        val publicApi = setOf("dev.totipo:totipo-storage-nio:$releaseVersion", "dev.totipo:totipo-core:$releaseVersion")
        check(coordinates(compileArtifacts.get()) == publicApi)
        val runtime = coordinates(runtimeArtifacts.get())
        check(runtime == publicApi + "org.bouncycastle:bcprov-jdk18on:1.86")
        runtimeArtifacts.get().incoming.artifacts.artifacts.forEach {
            check(!it.file.name.contains("test"))
            check(it.variant.capabilities.none { capability -> capability.name.contains("fixtures") })
        }
        println("compile: ${publicApi.sorted()}")
        println("runtime: ${runtime.sorted()}")
    }
}
tasks.check { dependsOn(verifyBoundary) }
