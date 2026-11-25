package org.grinsight.fly;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import android.util.JsonReader;
import android.util.JsonToken;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.util.UUID;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Keeps the wallet process (libfly_paycore_host.so) running in its own
 * Android process (":core"), so an open wallet keeps receiving payments and
 * messages while the window is closed. The window talks to it over the
 * abstract local socket "org.grinsight.fly.core"; only this app's own
 * processes are let through (the caller's uid is checked on every
 * connection). Lines go through unchanged, except the service's own request
 * "service.restart" (the user changed how the process is started).
 * Locking stays the window's "Lock"; the service never holds the wallet's
 * keys or reads what goes through it. The one thing it gives the wallet
 * process itself is the device's key for the rollback guard (DeviceKey),
 * as the first line of its input.
 */
public class CoreService extends Service {
    private static final String SOCKET = "org.grinsight.fly.core";
    private static final String CHANNEL = "core";
    private static final int MAX_LINE = 1024 * 1024 + 1024;

    /** Guards the host process and its input. */
    private final Object lock = new Object();
    /** Guards the window's output; separate, so a busy host cannot stop its own output. */
    private final Object windowLock = new Object();
    private java.lang.Process host;
    private OutputStream hostIn;
    private OutputStream client;
    private final WindowFence fence = new WindowFence();
    private InputStream activeOutput;
    /** The window's socket, closed when another window takes its place. */
    private LocalSocket clientSocket;
    private LocalServerSocket server;

    @Override
    public void onCreate() {
        super.onCreate();
        startForegroundNotice();
        startHost();
        Thread accept = new Thread(this::acceptLoop, "core-accept");
        accept.setDaemon(true);
        accept.start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        synchronized (lock) {
            stopHost();
        }
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {
        }
        super.onDestroy();
    }

    private void startForegroundNotice() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "GrinSight", NotificationManager.IMPORTANCE_LOW));
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, FlyActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification n = b.setContentTitle("GrinSight")
                .setContentText("Wallet process running · open to lock")
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentIntent(open)
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(1, n);
        }
    }

    private List<String> hostArgs() {
        String lib = getApplicationInfo().nativeLibraryDir;
        String files = getFilesDir().getAbsolutePath();
        List<String> a = new ArrayList<>();
        a.add(lib + "/libfly_paycore_host.so");
        a.add("--profile"); a.add(files + "/profile");
        a.add("--guard-dir"); a.add(files + "/guard");
        // the first line of its input is the device's key for the guard
        a.add("--device-key-stdin");
        // the window's choices (ui.txt next to the profile): "send directly if Tor
        // fails", and the two parts the owner can switch off - Tor and Nostr
        boolean direct = false, torOff = false, nostrOff = false;
        try {
            for (String line : Files.readAllLines(new File(files, "ui.txt").toPath(), StandardCharsets.UTF_8)) {
                String word = line.trim();
                if (word.equals("direct=on")) direct = true;
                if (word.equals("tor=off")) torOff = true;
                if (word.equals("nostr=off")) nostrOff = true;
            }
        } catch (IOException ignored) {
        }
        a.add("--chain"); a.add(lib + "/libfly_chain.so");
        // what is switched off is not started: without Tor neither the program
        // for the address nor the message program (it speaks through Tor)
        if (!torOff) {
            a.add("--onion"); a.add(lib + "/libfly_onion.so");
        }
        if (!torOff && !nostrOff) {
            a.add("--transport"); a.add(lib + "/libfly_mailbox.so");
            a.add("--relay"); a.add("wss://relay.floonet.dev");
        }
        // the user's choice of Tor bridges: a file next to the profile, written by the window
        a.add("--tor-bridges"); a.add(files + "/tor-bridges.txt");
        if (torOff) a.add("--chain-no-tor");
        if (direct) a.add("--chain-direct-post");
        return a;
    }

    private void startHost() {
        synchronized (lock) {
            try {
                ProcessBuilder pb = new ProcessBuilder(hostArgs());
                pb.directory(getFilesDir());
                pb.redirectError(ProcessBuilder.Redirect.to(new File("/dev/null")));
                host = pb.start();
                hostIn = host.getOutputStream();
                giveDeviceKey(hostIn);
                final InputStream out = host.getInputStream();
                synchronized (windowLock) { activeOutput = out; }
                Thread t = new Thread(() -> pumpHostOut(out), "core-host-out");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                // started but not told its first line: it is of no use
                if (host != null) host.destroy();
                host = null;
                hostIn = null;
            }
        }
    }

    /**
     * The one line the wallet process expects before any request: the key
     * the Keystore keeps for the rollback guard, or an empty key when the
     * Keystore cannot be used (the guard is then tied to the password
     * alone, and the wallet's status says so). Called under lock, before
     * any window's line can be written.
     */
    private void giveDeviceKey(OutputStream to) throws IOException {
        byte[] key = DeviceKey.load(getFilesDir());
        byte[] line = DeviceKeyFile.line(key);
        try {
            to.write(line);
            to.flush();
        } finally {
            java.util.Arrays.fill(line, (byte) 0);
            if (key != null) java.util.Arrays.fill(key, (byte) 0);
        }
    }

    private void stopHost() {
        if (host == null) return;
        synchronized (windowLock) { activeOutput = null; }
        try {
            // end of input: the host locks the profile and exits
            hostIn.close();
        } catch (IOException ignored) {
        }
        try {
            if (!host.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) host.destroy();
        } catch (InterruptedException e) {
            host.destroy();
        }
        host = null;
        hostIn = null;
    }

    // Inspect only a top-level receipt id while switching windows. Normal
    // replies and notifications are forwarded as their original bytes.
    private static String stringId(byte[] frame) {
        try (JsonReader reader = new JsonReader(new InputStreamReader(
                new ByteArrayInputStream(frame), StandardCharsets.UTF_8))) {
            reader.beginObject();
            while (reader.hasNext()) {
                if (reader.nextName().equals("id") && reader.peek() == JsonToken.STRING) {
                    return reader.nextString();
                }
                reader.skipValue();
            }
        } catch (IOException | IllegalStateException ignored) {
        }
        return null;
    }

    // Called under lock, after selecting a window and before its first call.
    private void writeFence(String marker) throws IOException {
        if (hostIn == null) throw new IOException("core unavailable");
        String request = "{\"jsonrpc\":\"2.0\",\"method\":\"host.status\",\"id\":\"" + marker + "\"}\n";
        hostIn.write(request.getBytes(StandardCharsets.UTF_8));
        hostIn.flush();
    }

    private void pumpHostOut(InputStream out) {
        try (InputStream in = new BufferedInputStream(out, 65536)) {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            while (true) {
                int length = readLine(in, line, true);
                if (length < 0) return;
                if (length > MAX_LINE) continue;
                synchronized (windowLock) {
                    if (activeOutput != out || client == null) continue;
                    if (fence.waiting() && !fence.deliver(stringId(line.toByteArray()))) continue;
                    try {
                        line.writeTo(client);
                        client.write('\n');
                        client.flush();
                    } catch (IOException ignored) {
                        client = null;
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    private void acceptLoop() {
        try {
            server = new LocalServerSocket(SOCKET);
        } catch (IOException e) {
            return;
        }
        while (true) {
            LocalSocket s;
            try {
                s = server.accept();
            } catch (IOException e) {
                return;
            }
            try {
                // only this app's own processes
                if (s.getPeerCredentials().getUid() != Process.myUid()) {
                    s.close();
                    continue;
                }
                serve(s);
            } catch (IOException e) {
                try {
                    s.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /** One window at a time; a new one takes the place of the old, whose socket is closed. */
    private void serve(LocalSocket s) throws IOException {
        final OutputStream toWindow = s.getOutputStream();
        synchronized (lock) {
            LocalSocket old;
            String marker = "window-" + UUID.randomUUID();
            synchronized (windowLock) {
                fence.replace(marker);
                old = clientSocket;
                client = toWindow;
                clientSocket = s;
            }
            if (old != null) {
                try { old.close(); } catch (IOException ignored) {}
            }
            try {
                writeFence(marker);
            } catch (IOException e) {
                synchronized (windowLock) { client = null; clientSocket = null; }
                throw e;
            }
        }
        Thread t = new Thread(() -> {
            try (InputStream in = new BufferedInputStream(s.getInputStream(), 65536)) {
                ByteArrayOutputStream line = new ByteArrayOutputStream();
                while (true) {
                    // a line longer than MAX_LINE is skipped, never held whole
                    int got = readLine(in, line, false);
                    if (got < 0) break;
                    if (got > MAX_LINE) continue;
                    String text = new String(line.toByteArray(), StandardCharsets.UTF_8);
                    if (text.contains("\"method\":\"service.restart\"")) {
                        restart(text, toWindow);
                        continue;
                    }
                    synchronized (lock) {
                        synchronized (windowLock) { if (clientSocket != s) break; }
                        if (hostIn == null) break;
                        line.write('\n');
                        line.writeTo(hostIn);
                        hostIn.flush();
                    }
                }
            } catch (IOException ignored) {
            } finally {
                synchronized (windowLock) {
                    if (client == toWindow) {
                        client = null;
                        clientSocket = null;
                    }
                }
                try {
                    s.close();
                } catch (IOException ignored) {
                }
            }
        }, "core-window-in");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Reads one line without its newline into {@code into}, keeping at most
     * MAX_LINE + 1 bytes. Returns the line's length (more than MAX_LINE when
     * it was longer), or -1 at the end of the stream.
     */
    private static int readLine(InputStream in, ByteArrayOutputStream into, boolean requireNewline) throws IOException {
        into.reset();
        int length = 0;
        while (true) {
            int b = in.read();
            if (b < 0) return !requireNewline && length != 0 ? length : -1;
            if (b == '\n') return length;
            if (length <= MAX_LINE) into.write(b);
            if (length <= MAX_LINE) length++;
        }
    }

    /** The window changed how the host is started: start it again, answer the request. */
    private void restart(String line, OutputStream toWindow) {
        String id = "null";
        int at = line.indexOf("\"id\":");
        if (at >= 0) {
            int end = at + 5;
            while (end < line.length() && (Character.isDigit(line.charAt(end)))) end++;
            if (end > at + 5) id = line.substring(at + 5, end);
        }
        boolean up;
        synchronized (lock) {
            String marker = "window-" + UUID.randomUUID();
            synchronized (windowLock) {
                if (client != toWindow) return;
                fence.replace(marker);
            }
            stopHost();
            startHost();
            try {
                writeFence(marker);
                up = true;
            } catch (IOException e) {
                up = false;
            }
        }
        String answer = up
                ? "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{}}\n"
                : "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32049,\"message\":\"profile_io\",\"data\":{\"kind\":\"profile_io\",\"reason\":\"the wallet process did not start\"}}}\n";
        synchronized (windowLock) {
            try {
                toWindow.write(answer.getBytes(StandardCharsets.UTF_8));
                toWindow.flush();
            } catch (IOException ignored) {
            }
        }
    }
}
