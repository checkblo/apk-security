plugins {
    id("com.android.application")
}

android {
    namespace = "pl.cybertarcza.local"
    compileSdk = 35

    defaultConfig {
        applicationId = "pl.cybertarcza.local"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        if (System.getenv("CT_KEYSTORE_FILE") != null) {
            create("release") {
                storeFile = file(System.getenv("CT_KEYSTORE_FILE"))
                storePassword = System.getenv("CT_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("CT_KEY_ALIAS")
                keyPassword = System.getenv("CT_KEY_PASSWORD")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
                enableV4Signing = true
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (System.getenv("CT_KEYSTORE_FILE") != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
