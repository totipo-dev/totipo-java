rootProject.name = "totipo-maven-consumer-smoke"
// Remote verification deliberately has one repository and no staging fallback.
val remoteCentral = providers.gradleProperty("remoteCentral").isPresent
val pomOnly = providers.gradleProperty("pomOnly").isPresent
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        if (remoteCentral) {
            maven {
                name = "VerifiedMavenCentral"
                url = uri("https://repo.maven.apache.org/maven2/")
                content {
                    includeGroup("org.totipo")
                    includeModule("org.bouncycastle", "bcprov-jdk18on")
                }
                if (pomOnly) {
                    metadataSources { mavenPom(); ignoreGradleMetadataRedirection() }
                }
            }
        } else {
            exclusiveContent {
                forRepository { maven {
                    name = "TotipoStaging"
                    url = uri("../../build/repository")
                    if (pomOnly) {
                        metadataSources { mavenPom(); ignoreGradleMetadataRedirection() }
                    }
                } }
                filter { includeGroup("org.totipo") }
            }
            mavenCentral { content { includeModule("org.bouncycastle", "bcprov-jdk18on") } }
        }
    }
}

// Check the settings repositories without resolving an unpublished Totipo version.
val smokeRepositories = dependencyResolutionManagement.repositories.map {
    (it as MavenArtifactRepository).let { repository -> repository.name to repository.url }
}
gradle.rootProject {
    tasks.register("verifyRepositorySelection") {
        doLast {
            if (remoteCentral) {
                check(smokeRepositories.size == 1)
                check(smokeRepositories.single().second.toString() == "https://repo.maven.apache.org/maven2/")
            } else {
                check(smokeRepositories.any { it.first == "TotipoStaging" && it.second.scheme == "file" })
            }
            println("Repository selection verified: remoteCentral=$remoteCentral; $smokeRepositories")
        }
    }
}
