package org.grinsight.fly;

/**
 * The file the device's key for the rollback guard lies in: the 12 bytes the
 * cipher was started with, then the 32 bytes of the key sealed by the
 * Keystore's AES-GCM key (48 bytes with the tag). Nothing else is a file of
 * ours. Plain Java, so that it is tested without a phone.
 */
final class DeviceKeyFile {
    static final int KEY_LEN = 32;
    static final int IV_LEN = 12;
    static final int TAG_LEN = 16;
    static final int FILE_LEN = IV_LEN + KEY_LEN + TAG_LEN;

    private DeviceKeyFile() {
    }

    /** The file's bytes, or null when the parts are not of the right sizes. */
    static byte[] join(byte[] iv, byte[] sealed) {
        if (iv == null || sealed == null || iv.length != IV_LEN || sealed.length != KEY_LEN + TAG_LEN) return null;
        byte[] file = new byte[FILE_LEN];
        System.arraycopy(iv, 0, file, 0, IV_LEN);
        System.arraycopy(sealed, 0, file, IV_LEN, sealed.length);
        return file;
    }

    /** The cipher's start from a file, or null when it is not a file of ours. */
    static byte[] iv(byte[] file) {
        if (file == null || file.length != FILE_LEN) return null;
        byte[] iv = new byte[IV_LEN];
        System.arraycopy(file, 0, iv, 0, IV_LEN);
        return iv;
    }

    /** The sealed key from a file, or null when it is not a file of ours. */
    static byte[] sealed(byte[] file) {
        if (file == null || file.length != FILE_LEN) return null;
        byte[] sealed = new byte[KEY_LEN + TAG_LEN];
        System.arraycopy(file, IV_LEN, sealed, 0, sealed.length);
        return sealed;
    }

    /**
     * The one line the wallet process is given before any request
     * (`--device-key-stdin`): the key in lower-case hex, or an empty key when
     * the device keeps none. The key's bytes are wiped by the caller.
     */
    static byte[] line(byte[] key) {
        byte[] head = "{\"jsonrpc\":\"2.0\",\"method\":\"host.device_key\",\"params\":{\"key\":\"".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] tail = "\"}}\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int digits = key != null && key.length == KEY_LEN ? KEY_LEN * 2 : 0;
        byte[] line = new byte[head.length + digits + tail.length];
        System.arraycopy(head, 0, line, 0, head.length);
        final byte[] hex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        for (int i = 0; i < digits / 2; i++) {
            line[head.length + 2 * i] = hex[(key[i] >> 4) & 15];
            line[head.length + 2 * i + 1] = hex[key[i] & 15];
        }
        System.arraycopy(tail, 0, line, head.length + digits, tail.length);
        return line;
    }
}
