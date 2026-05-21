pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://repo.danubetech.com/repository/maven-public/") }
        maven { url = uri("https://jitpack.io") }
        maven { url = uri("https://central.sonatype.com/repository/maven-snapshots/") }
    }
}

rootProject.name = "kotlin"
include(":openID4VP")
include(":sampleovpwallet")