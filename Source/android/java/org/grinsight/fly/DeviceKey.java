package org.grinsight.fly;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The device's key for the wallet's rollback guard. It is 32 random bytes
 * kept in the app's files only sealed under an AES key of the Android
 * Keystore; that key is made on the phone and does not leave it. The wallet
 * process wraps the guard's own key with it (over the key from the
 * password), so a profile copied to another phone, or put back from a copy
 * after the app's data was cleared, arrives without a guard that opens, and
 * the wallet says so.
 *
 * This is not a key of the wallet: no money can be spent with it, and it
 * alone opens nothing. It is read once at the start of the wallet process
 * and wiped here.
 */
final class DeviceKey {
    private static final String TAG = "grinsight";
    private static final String ALIAS = "fly-guard-v1";
    private static final String FILE = "device.key";
    private static final String CIPHER = "AES/GCM/NoPadding";

    private DeviceKey() {
    }

    /**
     * The key, made on first use; null when the Keystore cannot be used now.
     * A file that this phone's Keystore key does not open (another phone's
     * file, or the Keystore key is gone) is replaced by a new key: the old
     * one cannot be had back by anybody. An error that says nothing about
     * the file leaves everything as it is.
     */
    static byte[] load(File dir) {
        File file = new File(dir, FILE);
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            if (file.isFile() && store.containsAlias(ALIAS)) {
                byte[] kept = open(store, Files.readAllBytes(file.toPath()));
                if (kept != null) {
                    Log.i(TAG, "guard: the device key is opened");
                    return kept;
                }
            }
            byte[] made = make(store, file);
            Log.i(TAG, "guard: a device key is made");
            return made;
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            // the class of the error only: nothing of the key is in it
            Log.w(TAG, "guard: the Keystore cannot be used: " + e.getClass().getSimpleName());
            return null;
        }
    }

    /** The key in the file, or null when this phone's Keystore key does not open it. */
    private static byte[] open(KeyStore store, byte[] raw) throws GeneralSecurityException {
        byte[] iv = DeviceKeyFile.iv(raw);
        byte[] sealed = DeviceKeyFile.sealed(raw);
        if (iv == null || sealed == null) return null;
        if (!(store.getKey(ALIAS, null) instanceof SecretKey)) return null;
        SecretKey key = (SecretKey) store.getKey(ALIAS, null);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(DeviceKeyFile.TAG_LEN * 8, iv));
            byte[] plain = cipher.doFinal(sealed);
            if (plain.length != DeviceKeyFile.KEY_LEN) {
                Arrays.fill(plain, (byte) 0);
                return null;
            }
            return plain;
        } catch (AEADBadTagException | KeyPermanentlyInvalidatedException e) {
            return null;
        }
    }

    private static byte[] make(KeyStore store, File file) throws GeneralSecurityException, IOException {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        SecretKey key = generator.generateKey();
        byte[] secret = new byte[DeviceKeyFile.KEY_LEN];
        new SecureRandom().nextBytes(secret);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] raw = DeviceKeyFile.join(cipher.getIV(), cipher.doFinal(secret));
        if (raw == null) {
            Arrays.fill(secret, (byte) 0);
            throw new IOException("sealed key of an unexpected size");
        }
        // the sealed key must open again before anything relies on it
        byte[] back = open(store, raw);
        boolean same = back != null && Arrays.equals(back, secret);
        if (back != null) Arrays.fill(back, (byte) 0);
        if (!same) {
            Arrays.fill(secret, (byte) 0);
            throw new IOException("sealed key does not open");
        }
        File tmp = new File(file.getPath() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(raw);
            out.getFD().sync();
        }
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return secret;
    }
}
