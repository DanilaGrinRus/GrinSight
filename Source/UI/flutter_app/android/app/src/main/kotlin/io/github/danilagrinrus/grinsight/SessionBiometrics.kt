package io.github.danilagrinrus.grinsight

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Experimental: per-profile encrypted password, opt-in, device-auth gated. */
class SessionBiometrics(private val activity: Activity) {
    private val keys: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    // MethodChannel and BiometricPrompt callbacks run on the Android main thread;
    // gate every Activity instance in this app process, including recreation.
    private companion object {
        var active: CancellationSignal? = null
        var cancelPending: (() -> Unit)? = null
    }
    private var cancelOwn: (() -> Unit)? = null
    private val storeDir: File get() = File(activity.noBackupFilesDir, "biometric-v1")

    private fun identity(call: MethodCall): Pair<String, ByteArray> {
        val network = call.argument<String>("network") ?: throw IllegalArgumentException()
        val profile = call.argument<String>("profile") ?: throw IllegalArgumentException()
        require(network == "mainnet" || network == "floonet")
        require(profile.length in 1..32 && profile.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-' })
        val aad = "grinsight-biometric-v1\u0000$network\u0000$profile".toByteArray(Charsets.UTF_8)
        val hash = MessageDigest.getInstance("SHA-256").digest(aad)
        val hex = hash.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        hash.fill(0)
        return Pair(hex, aad)
    }

    private fun available(): Boolean {
        if (Build.VERSION.SDK_INT < 28) return false
        val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isDeviceSecure) return false
        if (Build.VERSION.SDK_INT >= 30) {
            val bm = activity.getSystemService(BiometricManager::class.java)
            val methods = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            return bm.canAuthenticate(methods) == BiometricManager.BIOMETRIC_SUCCESS
        }
        if (Build.VERSION.SDK_INT == 29) {
            @Suppress("DEPRECATION")
            return activity.getSystemService(BiometricManager::class.java).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS
        }
        @Suppress("DEPRECATION")
        val fp = activity.getSystemService(Context.FINGERPRINT_SERVICE) as? android.hardware.fingerprint.FingerprintManager
        @Suppress("DEPRECATION")
        return fp?.isHardwareDetected == true && fp.hasEnrolledFingerprints()
    }

    private fun keyAlias(id: String): String = "grinsight.bio.$id.${UUID.randomUUID()}"
    private fun path(id: String): File = File(storeDir, "$id.json")

    /** Bind the credential to this exact encrypted vault, not just its name. */
    private fun vaultDigest(network: String, profile: String): ByteArray {
        // identity() has already validated both path components.
        val root = File(activity.filesDir, "data/profiles/$network").canonicalFile
        val directory = File(root, profile).canonicalFile
        val file = File(directory, "vault.json").canonicalFile
        require(directory.parentFile == root && file.parentFile == directory && file.isFile && file.length() in 1..1048576)
        val hash = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(4096)
            var count: Int
            var total = 0
            while (input.read(buffer).also { count = it } != -1) {
                total += count
                require(total <= 1048576)
                hash.update(buffer, 0, count)
            }
            buffer.fill(0)
        }
        return hash.digest()
    }

    private fun load(id: String): JSONObject? {
        val file = path(id)
        if (!file.isFile && !File(file.path + ".bak").isFile) return null
        val bytes = AtomicFile(file).openRead().use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (out.size() <= 16384) {
                val count = input.read(buffer, 0, minOf(buffer.size, 16385 - out.size()))
                if (count < 0) break
                if (count == 0) throw IllegalStateException()
                out.write(buffer, 0, count)
            }
            buffer.fill(0)
            out.toByteArray()
        }
        require(bytes.size in 1..16384)
        val obj = JSONObject(String(bytes, Charsets.UTF_8))
        require(obj.getInt("v") == 1)
        val alias = obj.getString("alias")
        require(alias.startsWith("grinsight.bio.$id.") && alias.length < 200)
        return obj
    }

    /** Remove only uncommitted aliases for this exact profile after a crash. */
    private fun cleanupOrphans(id: String) {
        if (active != null) return
        // If metadata is corrupt, load() throws and no aliases are deleted.
        val keep = load(id)?.optString("alias")
        val prefix = "grinsight.bio.$id."
        val aliases = keys.aliases()
        val stale = mutableListOf<String>()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (alias.startsWith(prefix) && alias != keep) stale.add(alias)
        }
        stale.forEach { keys.deleteEntry(it) }
    }

    private fun makeKey(alias: String): SecretKey {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        gen.init(builder.build())
        return gen.generateKey()
    }

    private fun prompt(cipher: Cipher, aad: ByteArray, result: MethodChannel.Result,
                       onSuccess: (Cipher) -> Any?, onError: () -> Unit = {}) {
        if (active != null) { aad.fill(0); onError(); result.error("busy", "Authentication already in progress", null); return }
        val cancel = CancellationSignal()
        active = cancel
        var completed = false
        fun fail() {
            if (completed) return
            completed = true
            active = null; cancelPending = null; cancelOwn = null; aad.fill(0); onError()
            result.error("biometric_cancelled", "Use wallet password", null)
        }
        cancelPending = { cancel.cancel(); fail() }
        cancelOwn = cancelPending
        val builder = BiometricPrompt.Builder(activity)
            .setTitle("Подтвердите вход в GrinSight")
            .setSubtitle("Или отмените и используйте пароль кошелька")
        if (Build.VERSION.SDK_INT >= 30) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            builder.setNegativeButton("Отмена", activity.mainExecutor) { _, _ -> cancel.cancel() }
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(code: Int, message: CharSequence) {
                fail()
            }
            override fun onAuthenticationSucceeded(authentication: BiometricPrompt.AuthenticationResult) {
                if (completed || active !== cancel || cancel.isCanceled) { fail(); return }
                completed = true
                active = null; cancelPending = null; cancelOwn = null
                try { result.success(onSuccess(authentication.cryptoObject?.cipher ?: throw IllegalStateException())) }
                catch (_: Exception) { onError(); result.error("biometric_unavailable", "Use wallet password", null) }
                finally { aad.fill(0) }
            }
        }
        try { builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), cancel, activity.mainExecutor, callback) }
        catch (_: Exception) { fail() }
    }

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        if (call.method == "supported") { result.success(Build.VERSION.SDK_INT >= 28); return }
        if (call.method == "available") { result.success(available()); return }
        if (Build.VERSION.SDK_INT < 28) { result.error("biometric_unavailable", "Use wallet password", null); return }
        try {
            if (call.method == "forgetAll") {
                require(active == null)
                val aliases = keys.aliases()
                val owned = mutableListOf<String>()
                while (aliases.hasMoreElements()) {
                    val alias = aliases.nextElement()
                    if (alias.startsWith("grinsight.bio.")) owned.add(alias)
                }
                owned.forEach { keys.deleteEntry(it) }
                if (storeDir.exists()) {
                    val files = storeDir.listFiles() ?: throw IllegalStateException()
                    files.filter { it.name.matches(Regex("[a-f0-9]{64}\\.json(\\.(bak|new))?")) }.forEach {
                        if (!it.delete() && it.exists()) throw IllegalStateException()
                    }
                }
                result.success(true)
                return
            }
            val (id, aad) = identity(call)
            val network = call.argument<String>("network") ?: throw IllegalArgumentException()
            val profile = call.argument<String>("profile") ?: throw IllegalArgumentException()
            when (call.method) {
                "hasStoredCredential" -> {
                    val file = path(id)
                    fun present(path: String): Boolean = try {
                        android.system.Os.lstat(path); true
                    } catch (e: android.system.ErrnoException) {
                        if (e.errno == android.system.OsConstants.ENOENT) false else throw e
                    }
                    val exists = present(file.path) || present(file.path + ".bak")
                    aad.fill(0); result.success(exists)
                }
                "hasCredential" -> {
                    cleanupOrphans(id)
                    val obj = load(id)
                    val current = vaultDigest(network, profile)
                    val expected = obj?.optString("vault")?.let { Base64.decode(it, Base64.NO_WRAP) }
                    val alias = obj?.optString("alias")
                    val matches = expected != null && !alias.isNullOrBlank() && keys.containsAlias(alias) && MessageDigest.isEqual(current, expected)
                    current.fill(0); expected?.fill(0); aad.fill(0); result.success(matches)
                }
                "forget" -> {
                    require(active == null)
                    val prefix = "grinsight.bio.$id."
                    val aliases = keys.aliases()
                    val stale = mutableListOf<String>()
                    while (aliases.hasMoreElements()) {
                        val alias = aliases.nextElement()
                        if (alias.startsWith(prefix)) stale.add(alias)
                    }
                    AtomicFile(path(id)).delete()
                    stale.forEach { keys.deleteEntry(it) }
                    aad.fill(0); result.success(true)
                }
                "enroll" -> {
                    require(available())
                    cleanupOrphans(id)
                    val previous = load(id)?.optString("alias")
                    val digest = vaultDigest(network, profile)
                    val expectedHex = call.argument<String>("vault_digest") ?: throw IllegalArgumentException()
                    require(expectedHex.matches(Regex("[0-9a-f]{64}")))
                    val expected = expectedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                    val digestMatches = MessageDigest.isEqual(expected, digest)
                    expected.fill(0)
                    require(digestMatches)
                    val credentialAad = aad + digest
                    val alias = keyAlias(id)
                    val secret = (call.argument<String>("password") ?: throw IllegalArgumentException()).toByteArray(Charsets.UTF_8)
                    try {
                    require(secret.isNotEmpty() && secret.size <= 4096)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, makeKey(alias))
                    prompt(cipher, credentialAad, result, onSuccess = { authorized ->
                        val current = vaultDigest(network, profile)
                        val same = MessageDigest.isEqual(current, digest); current.fill(0)
                        require(same)
                        authorized.updateAAD(credentialAad)
                        val encrypted = authorized.doFinal(secret)
                        try {
                        val obj = JSONObject().put("v", 1).put("alias", alias)
                            .put("vault", Base64.encodeToString(digest, Base64.NO_WRAP))
                            .put("iv", Base64.encodeToString(authorized.iv, Base64.NO_WRAP))
                            .put("ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                        storeDir.mkdirs()
                        val atomic = AtomicFile(path(id))
                        val out = atomic.startWrite()
                        try { out.write(obj.toString().toByteArray(Charsets.UTF_8)); out.fd.sync(); atomic.finishWrite(out) }
                        catch (e: Exception) { atomic.failWrite(out); throw e }
                        } finally { encrypted.fill(0); secret.fill(0); digest.fill(0); aad.fill(0) }
                        if (!previous.isNullOrBlank() && previous != alias) try { keys.deleteEntry(previous) } catch (_: Exception) {}
                        true
                    }, onError = { secret.fill(0); digest.fill(0); aad.fill(0); try { keys.deleteEntry(alias) } catch (_: Exception) {} })
                    } catch (e: Exception) {
                        secret.fill(0); digest.fill(0); credentialAad.fill(0); aad.fill(0)
                        try { keys.deleteEntry(alias) } catch (_: Exception) {}
                        throw e
                    }
                }
                "unlockSecret" -> {
                    require(available())
                    val obj = load(id) ?: throw IllegalArgumentException()
                    val digest = vaultDigest(network, profile)
                    val expected = Base64.decode(obj.getString("vault"), Base64.NO_WRAP)
                    require(expected.size == 32 && MessageDigest.isEqual(digest, expected))
                    expected.fill(0)
                    val credentialAad = aad + digest
                    val alias = obj.getString("alias")
                    val iv = Base64.decode(obj.getString("iv"), Base64.NO_WRAP)
                    val encrypted = Base64.decode(obj.getString("ciphertext"), Base64.NO_WRAP)
                    require(iv.size == 12 && encrypted.size in 17..4112)
                    val key = keys.getKey(alias, null) as? SecretKey ?: throw IllegalStateException()
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                    prompt(cipher, credentialAad, result, onSuccess = { authorized ->
                        val current = vaultDigest(network, profile)
                        val same = MessageDigest.isEqual(current, digest); current.fill(0)
                        require(same)
                        authorized.updateAAD(credentialAad)
                        val plain = authorized.doFinal(encrypted)
                        try {
                            mapOf("password" to String(plain, Charsets.UTF_8),
                                "vault_digest" to digest.joinToString("") { "%02x".format(it.toInt() and 0xff) })
                        } finally { plain.fill(0); encrypted.fill(0); digest.fill(0); aad.fill(0) }
                    }, onError = { encrypted.fill(0); digest.fill(0); aad.fill(0) })
                }
                else -> { aad.fill(0); result.notImplemented() }
            }
        } catch (_: Exception) {
            result.error("biometric_unavailable", "Use wallet password", null)
        }
    }

    fun cancel() { cancelOwn?.invoke(); cancelOwn = null }
}
