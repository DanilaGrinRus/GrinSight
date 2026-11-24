package org.grinsight.fly;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Offline contract: the file of the device key and the one line the wallet process is given. */
public final class DeviceKeyFileTest {
    private DeviceKeyFileTest() {
    }

    private static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    public static void main(String[] args) {
        byte[] iv = new byte[12];
        byte[] sealed = new byte[48];
        for (int i = 0; i < iv.length; i++) iv[i] = (byte) (i + 1);
        for (int i = 0; i < sealed.length; i++) sealed[i] = (byte) (200 + i);
        byte[] file = DeviceKeyFile.join(iv, sealed);
        check(file != null && file.length == 60, "a file is sixty bytes");
        check(Arrays.equals(DeviceKeyFile.iv(file), iv) && Arrays.equals(DeviceKeyFile.sealed(file), sealed), "the parts come back");
        // nothing of another size is a file of ours
        check(DeviceKeyFile.join(new byte[11], sealed) == null && DeviceKeyFile.join(iv, new byte[47]) == null && DeviceKeyFile.join(null, sealed) == null, "parts of wrong sizes");
        for (byte[] wrong : new byte[][] {null, new byte[0], new byte[59], new byte[61]}) {
            check(DeviceKeyFile.iv(wrong) == null && DeviceKeyFile.sealed(wrong) == null, "a file of a wrong size");
        }
        // the line for the wallet process: exactly what it accepts
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 9 - 3);
        StringBuilder hex = new StringBuilder();
        for (byte b : key) hex.append(String.format("%02x", b & 255));
        String line = new String(DeviceKeyFile.line(key), StandardCharsets.US_ASCII);
        check(line.equals("{\"jsonrpc\":\"2.0\",\"method\":\"host.device_key\",\"params\":{\"key\":\"" + hex + "\"}}\n"), line);
        String none = "{\"jsonrpc\":\"2.0\",\"method\":\"host.device_key\",\"params\":{\"key\":\"\"}}\n";
        check(new String(DeviceKeyFile.line(null), StandardCharsets.US_ASCII).equals(none), "no key: an empty one");
        check(new String(DeviceKeyFile.line(new byte[31]), StandardCharsets.US_ASCII).equals(none), "a key of a wrong size is no key");
        System.out.println("the device key file and the line for the wallet process: passed");
    }
}
