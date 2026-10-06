import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.silvermine.plugin.connectivity"
    compileSdk = 37

    defaultConfig {
        minSdk = 23

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

// Match on the project directory as well as the path: a consuming Tauri app may
// have its own `:lib` module.
if (findProject(":lib")?.projectDir == file("lib")) {
    // Standalone build: depend on :lib as a separate module so its unit tests
    // can run on the JVM without the Android framework or the Tauri Android API.
    dependencies {
        implementation(project(":lib"))
    }
} else {
    // Tauri subproject build: the app's `settings.gradle` includes only this
    // module, so compile the :lib sources directly.
    android.sourceSets["main"].java.srcDir("lib/src/main/java")
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    if (findProject(":tauri-android") != null) {
        implementation(project(":tauri-android"))
    }
}
