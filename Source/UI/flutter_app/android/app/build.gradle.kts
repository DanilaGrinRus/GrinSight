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

// Flutter передаёт выбранные архитектуры в -Ptarget-platform. Нельзя класть
// ABI, для которого Flutter не собрал libflutter.so: Android предпочтёт его
// на соответствующем устройстве и приложение не запустится.
val coreTargets = mapOf("android-arm" to "armeabi-v7a", "android-arm64" to "arm64-v8a", "android-x64" to "x86_64")
val targetProperty = project.findProperty("target-platform")?.toString()
val targetPlatforms = if (targetProperty == null) listOf("android-arm64", "android-x64") else targetProperty.split(",")
val targetAbis = targetPlatforms.map { target ->
    coreTargets[target] ?: throw GradleException(
        "Для платформы $target нет ядра GrinSight. Выберите android-arm, android-arm64 и/или android-x64.",
    )
}.distinct()
val requiredCoreLibraries = listOf("libgrinsight_service.so", "libgrinsight_tor.so", "libgrinsight_pt.so", "libreverse_wtema_header_sync.so")
for (abi in targetAbis) {
    for (library in requiredCoreLibraries) {
        val binary = androidCoreJniLibs.resolve("$abi/$library")
        if (!binary.isFile) {
            throw GradleException("Нет ядра $library для ABI $abi в $androidCoreJniLibs. Соберите ядро до сборки APK.")
        }
        val header = binary.inputStream().use { it.readNBytes(20) }
        val expectedMachine = when (abi) { "armeabi-v7a" -> 40; "arm64-v8a" -> 183; else -> 62 }
        val expectedClass = if (abi == "armeabi-v7a") 1 else 2
        val machine = if (header.size >= 20) (header[18].toInt() and 0xff) or ((header[19].toInt() and 0xff) shl 8) else -1
        if (header.size < 20 || header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() ||
            header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte() ||
            header[4] != expectedClass.toByte() || header[5] != 1.toByte() || machine != expectedMachine) {
            throw GradleException("Неверная архитектура или ELF-заголовок $binary (ожидается $abi).")
        }
    }
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
        // Состав APK должен совпадать с тем, что собирает Flutter.
        ndk {
            abiFilters.clear()
            abiFilters.addAll(targetAbis)
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
