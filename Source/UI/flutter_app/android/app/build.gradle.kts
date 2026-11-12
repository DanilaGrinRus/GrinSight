import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Ключ подписи release. Файл не в репозитории; его делает владелец один раз
// (см. раздел «Ключ подписи» в UI/TASK_ANDROID_APK_RU.md).
val keystorePropertiesFile = rootProject.file("key.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    FileInputStream(keystorePropertiesFile).use { keystoreProperties.load(it) }
}

// Ядро для Android (libgrinsight_service.so и соседи) собирает make_android.ps1.
// Без него APK собрать нельзя — сразу понятная ошибка вместо пустого APK.
val androidCoreJniLibs = file("../../../../dist/android/jniLibs")
if (!androidCoreJniLibs.isDirectory) {
    throw GradleException(
        "Ядро для Android не собрано: нет каталога ${androidCoreJniLibs}.\n" +
            "Запустите .\\make_android.ps1 в корне GrinSight, затем повторите сборку APK.",
    )
}

android {
    namespace = "io.github.danilagrinrus.grinsight"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // Публичный идентификатор приложения. Менять только до первой публикации:
        // после этого смена applicationId ломает обновления у пользователей.
        applicationId = "io.github.danilagrinrus.grinsight"
        // Бинарники ядра собраны под API 24.
        minSdk = 24
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // Ядро собрано только под arm64. Flutter-плагин к этому моменту уже
        // положил в abiFilters полный список (arm64-v8a, armeabi-v7a, x86_64),
        // поэтому не добавляем, а заменяем его.
        ndk {
            abiFilters.clear()
            abiFilters.add("arm64-v8a")
            // x86_64 нужен только для эмулятора (реальные телефоны — arm64).
            abiFilters.add("x86_64")
        }
    }

    signingConfigs {
        // В окружениях без доступа к %USERPROFILE%\.android AGP не может создать
        // debug.keystore по пути по умолчанию (AccessDeniedException на *.lock).
        // Поэтому debug-ключ лежит в android\debug.keystore: он только для локальных
        // сборок, для релиза нужен свой ключ через key.properties.
        val localDebugKeystore = rootProject.file("debug.keystore")
        if (localDebugKeystore.exists()) {
            getByName("debug").apply {
                storeFile = localDebugKeystore
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
        if (keystorePropertiesFile.exists()) {
            create("release") {
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
            }
        }
    }

    buildTypes {
        release {
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            } else {
                // Временный режим: годный для установки и тестов, но не для релиза —
                // debug-ключом нельзя обновить приложение у пользователей.
                logger.lifecycle(
                    "ВНИМАНИЕ: android/key.properties не найден — release APK будет " +
                        "подписан debug-ключом. Для публикации создайте ключ (см. TASK_ANDROID_APK_RU.md).",
                )
                signingConfig = signingConfigs.getByName("debug")
            }
        }
    }

    // lib*.so — это программы ядра, которые приложение запускает как процессы.
    // Android разрешает запуск только из nativeLibraryDir, поэтому библиотеки
    // должны лежать там распакованными файлами (useLegacyPackaging заменяет
    // android:extractNativeLibs="true" из манифеста).
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    // Готовые бинарники подключаются из dist, а не копируются в репозиторий.
    sourceSets["main"].jniLibs.srcDirs(androidCoreJniLibs)
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
