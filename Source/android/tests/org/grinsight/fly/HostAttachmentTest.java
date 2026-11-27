package org.grinsight.fly;

import java.io.IOException;

/** Every replacement is a fresh locked process; an attachment retries only the fence. */
public final class HostAttachmentTest {
    public static void main(String[] args) throws IOException {
        for (boolean running : new boolean[]{false, true}) {
            int[] starts = {0};
            int[] markers = {0};
            HostAttachment.attach(running, () -> starts[0]++, () -> markers[0]++);
            if (markers[0] != 1 || starts[0] != (running ? 0 : 1)) throw new AssertionError();
        }
        int[] generation = {1};
        HostAttachment.attach(true, () -> generation[0]++, () -> {
            if (generation[0] == 1) throw new IOException("old pipe closed");
        });
        if (generation[0] != 2) throw new AssertionError();
        try {
            HostAttachment.attach(false, () -> generation[0]++, () -> { throw new IOException("unavailable"); });
            throw new AssertionError("failed attachment accepted");
        } catch (IOException expected) {
            if (generation[0] != 3) throw new AssertionError("unbounded restart");
        }
        System.out.println("live, exited, replaced and unavailable child attachment: passed");
    }
}
