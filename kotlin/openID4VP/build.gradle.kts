plugins {
    alias(libs.plugins.android.library)
    kotlin("multiplatform")
    alias(libs.plugins.dokka)
    `maven-publish`
    alias(libs.plugins.sonarqube)
    signing
    jacoco
    alias(libs.plugins.kotlin.serialization)
}

jacoco {
    toolVersion = "0.8.11"
    reportsDirectory = layout.buildDirectory.dir("reports/jacoco")
}

kotlin {
    jvmToolchain(17)

    androidTarget()

    jvm {
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.jetbrains.kotlinx.serialization.json)
                implementation(libs.okhttp3)
                implementation(libs.commons.codec)
                implementation(libs.jackson.module.kotlin)
                implementation(libs.jackson.databind)
                implementation(libs.jackson.core)
                implementation(libs.jackson.annotations)
                implementation(libs.nimbus.jose.jwt)
                implementation(libs.bouncyCastle)
                implementation(libs.identity.credential)
                implementation(libs.ld.signatures.java)
                implementation(libs.jsonld.common.java)
                implementation(libs.vcverifier)
                implementation(libs.bcpkix)
                implementation(libs.google.tink)
                implementation("com.augustcellars.cose:cose-java:1.1.0")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.junit)
                implementation(libs.mockk)
                implementation(libs.mockwebserver)
                implementation(libs.androidx.junit)
                implementation(libs.androidx.espresso.core)
                implementation(libs.jupiter.junit)
                implementation(libs.assertj)
            }
        }
        val jvmMain by getting
        val androidMain by getting
        val jvmTest by getting
        val androidUnitTest by getting

    }

}

android {
    namespace = "io.mosip.openid4vp"
    compileSdk = 34

    defaultConfig {
        minSdk = 23
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

tasks.withType<AbstractPublishToMaven>().configureEach {
    onlyIf {
        publication.name in listOf("aar", "jarRelease")
    }
}

val jacocoReportExcludes = listOf(
    "**/*Test*.*",
    "**/*\$WhenMappings.*",
    "**/*\$Companion.*",
    "**/R.class",
    "**/R$*.class",
    "**/BuildConfig.*",
    "**/Manifest*.*",
    "android/**/*.*"
)

tasks.register("jacocoJvmReport", JacocoReport::class) {
    dependsOn("jvmTest")
    reports {
        xml.required.set(true)
        html.required.set(true)
        xml.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/jacocoJvmReport/jacocoJvmReport.xml"))
        html.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/jacocoJvmReport/html"))
    }
    classDirectories.setFrom(
        fileTree("${layout.buildDirectory.get()}/classes/kotlin/jvm/main") {
            exclude(jacocoReportExcludes)
        }
    )
    sourceDirectories.setFrom(files("src/commonMain/kotlin", "src/jvmMain/kotlin"))
    executionData.setFrom(files("${layout.buildDirectory.get()}/jacoco/jvmTest.exec"))
}

tasks.register("jacocoAndroidReport", JacocoReport::class) {
    dependsOn("testDebugUnitTest")
    reports {
        xml.required.set(true)
        html.required.set(true)
        xml.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/jacocoAndroidReport/jacocoAndroidReport.xml"))
        html.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/jacocoAndroidReport/html"))
    }
    classDirectories.setFrom(
        fileTree("${layout.buildDirectory.get()}/tmp/kotlin-classes/debug") {
            exclude(jacocoReportExcludes)
        }
    )
    sourceDirectories.setFrom(files("src/commonMain/kotlin", "src/androidMain/kotlin"))
    executionData.setFrom(files("${layout.buildDirectory.get()}/jacoco/testDebugUnitTest.exec"))
}

tasks.register("jacocoAllReports") {
    dependsOn("jacocoJvmReport", "jacocoAndroidReport")
}

tasks.withType<Test>().configureEach {
    jacoco {
        isEnabled = true
    }
    when (name) {
        "jvmTest" -> finalizedBy("jacocoJvmReport")
        "testDebugUnitTest" -> finalizedBy("jacocoAndroidReport")
    }
}

tasks {
    register<Wrapper>("wrapper") {
        gradleVersion = "8.5"
    }
}

tasks.register("prepareKotlinBuildScriptModel"){}
tasks.register<Jar>("jarRelease") {
    dependsOn("dokkaJavadoc")
    dependsOn("assembleRelease")
    dependsOn("jvmJar")
}

tasks.register<Jar>("javadocJar") {
    dependsOn("dokkaJavadoc")
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml").get().outputs.files)
}
tasks.register("generatePom") {
    dependsOn("generatePomFileForAarPublication", "generatePomFileForJarReleasePublication")
}

afterEvaluate {
    val signTasks = listOf("signJarReleasePublication", "signAarPublication")
    val publishTasks = listOf(
        "publishAarPublicationToLocalMavenWithChecksumsRepository",
        "publishJarReleasePublicationToLocalMavenWithChecksumsRepository",
        "publishAarPublicationToMavenLocal",
        "publishJarReleasePublicationToMavenLocal",
        "publishAarPublicationToInji-openid4vpRepository",
        "publishJarReleasePublicationToInji-openid4vpRepository"
    )

    publishTasks.forEach { publishName ->
        tasks.findByName(publishName)?.dependsOn(signTasks[0], signTasks[1])
    }
}

apply(from = "publish-artifact.gradle")
var buildDir = project.layout.buildDirectory.get()
sonarqube {
    properties {
        property("sonar.java.binaries", "$buildDir/classes/kotlin/jvm/main, $buildDir/tmp/kotlin-classes/debug")
        property("sonar.language", "kotlin")
        property("sonar.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property("sonar.scm.disabled", "true")
        property("sonar.coverage.jacoco.xmlReportPaths",
            "$buildDir/reports/jacoco/jacocoJvmReport/jacocoJvmReport.xml," +
                "$buildDir/reports/jacoco/jacocoAndroidReport/jacocoAndroidReport.xml")
        property("sonar.sources", "src/commonMain/kotlin,src/jvmMain/kotlin,src/androidMain/kotlin")
        property("sonar.tests", "src/commonTest/kotlin,src/jvmTest/kotlin,src/androidUnitTest/kotlin")
    }
}

tasks.matching { it.name == "sonar" || it.name == "sonarqube" }.configureEach {
    dependsOn("jacocoJvmReport", "jacocoAndroidReport")
}


