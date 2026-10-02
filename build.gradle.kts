import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.api.tasks.wrapper.Wrapper
import org.gradle.external.javadoc.JavadocMemberLevel
import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    base
    id("com.vanniktech.maven.publish") version "0.37.0" apply false
}

description = "Totipo Java libraries"

val versionText = providers.fileContents(layout.projectDirectory.file("VERSION")).asText.orNull
    ?: error("VERSION is required")
require(Regex("[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?\n").matches(versionText)) {
    "VERSION must contain major.minor.patch, an optional Maven qualifier, and one final newline"
}
version = versionText.removeSuffix("\n")
val centralRelease = providers.gradleProperty("centralRelease").map { it.toBooleanStrict() }.getOrElse(false)
require(!centralRelease || gradle.startParameter.taskNames.none { it.substringAfterLast(':') == "publish" }) {
    "Use an explicit Central task with -PcentralRelease=true, never generic publish"
}


subprojects {
    apply(plugin = "java-library")
    group = "org.totipo"
    version = rootProject.version
    apply(plugin = "com.vanniktech.maven.publish")
    extensions.configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
        coordinates("org.totipo", "totipo-${project.name}", project.version.toString())
        // Archives already belong to the Java component; avoid duplicate plugin tasks/fixtures sources.
        configure(com.vanniktech.maven.publish.JavaLibrary(
            javadocJar = com.vanniktech.maven.publish.JavadocJar.None(),
            sourcesJar = com.vanniktech.maven.publish.SourcesJar.None(),
        ))
        if (centralRelease) {
            publishToMavenCentral(automaticRelease = false)
            signAllPublications()
        }
        pom {
            name.set(if (project.name == "core") "Totipo Java Core" else "Totipo Java NIO Storage")
            description.set(if (project.name == "core") "Portable Totipo protocol/application API and core implementation" else "Filesystem/NIO entry point and storage provider for Totipo, exposing core transitively")
            url.set("https://github.com/totipo-org/totipo-java")
            licenses { license {
                name.set("Apache License 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            } }
            developers { developer {
                id.set("ingon")
                name.set("Nikolay Petrov")
                url.set("https://github.com/ingon/")
            } }
            scm {
                url.set("https://github.com/totipo-org/totipo-java")
                connection.set("scm:git:https://github.com/totipo-org/totipo-java.git")
                developerConnection.set("scm:git:ssh://git@github.com/totipo-org/totipo-java.git")
            }
        }
    }
    if (!centralRelease) {
        extensions.configure<PublishingExtension> {
            repositories { maven {
                name = "Staging"
                url = rootProject.layout.buildDirectory.dir("repository").get().asFile.toURI()
            } }
        }
    }
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }

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
        lockMode.set(LockMode.STRICT)
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

// Python standard library only; no extra build or runtime dependency resolution.
tasks.register<Exec>("verifyPublication") {
    group = "verification"
    dependsOn(subprojects.map { "${it.path}:publishAllPublicationsToStagingRepository" })
    commandLine("python3", "publishing/verify-publication.py")
}
// Deliberately separate Gradle build, with no composite/source substitution.
tasks.register<Exec>("consumerSmoke") {
    group = "verification"
    dependsOn("verifyPublication")
    commandLine("./gradlew", "-p", "publishing/consumer-smoke", "--offline", "clean", "check")
}
