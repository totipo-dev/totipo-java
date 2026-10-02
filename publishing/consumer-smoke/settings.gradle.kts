rootProject.name = "totipo-maven-consumer-smoke"
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository { maven {
                name = "TotipoStaging"
                url = uri("../../build/repository")
                if (providers.gradleProperty("pomOnly").isPresent) {
                    metadataSources { mavenPom(); ignoreGradleMetadataRedirection() }
                }
            } }
            filter { includeGroup("org.totipo") }
        }
        mavenCentral { content { includeModule("org.bouncycastle", "bcprov-jdk18on") } }
    }
}
