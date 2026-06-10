plugins {
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.0"
    id("com.android.application")
    id("org.jetbrains.kotlin.android") version "2.0.0"
}


configurations.all {

    exclude(module = "bcprov-jdk15to18")
    exclude(module = "bcutil-jdk18on")
    exclude(module = "bcprov-jdk15on")
    exclude(module = "bcutil-jdk15on")
    exclude(module = "titanium-json-ld")
}


android {
    namespace = "io.mosip.sampleovpwallet"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.mosip.sampleovpwallet"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
    }
    packagingOptions {

        resources {
            excludes += listOf(
                "META-INF/*",
                "META-INF/spring/aot.factories"
            )
        }
    }
    lint {
        disable += setOf(
            "HardcodedText",
            "MissingTranslation",
            "NewApi",
            "SetTextI18n"
        )
        abortOnError = false
        checkReleaseBuilds = false
    }
}


dependencies {
    implementation(project(":openID4VP")) {
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
        exclude(group = "com.google.crypto.tink", module = "tink")
        exclude(group = "com.augustcellars.cose", module = "cose-java")
    }

    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    implementation(platform("androidx.compose:compose-bom:2024.04.01"))
    implementation("androidx.core:core-ktx:1.9.0")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.compose.material:material:1.5.4")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("androidx.camera:camera-core:1.2.3")
    implementation("androidx.camera:camera-camera2:1.2.3")
    implementation("androidx.camera:camera-lifecycle:1.2.3")
    implementation("androidx.camera:camera-view:1.2.3")

    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.google.mlkit:barcode-scanning:17.0.3")
    implementation("com.google.accompanist:accompanist-permissions:0.30.1")
    implementation("androidx.concurrent:concurrent-futures:1.1.0")
    implementation("com.google.guava:guava:31.1-android")
    implementation("com.jayway.jsonpath:json-path:2.9.0")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.0")
    implementation("com.nimbusds:nimbus-jose-jwt:9.31")
    implementation("com.google.crypto.tink:tink-android:1.6.1")
    implementation("io.mosip:pixelpass-aar:0.6.0")

    androidTestImplementation("androidx.test:core:1.5.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
    testImplementation("junit:junit:4.13.2")


}
