package org.grinsight.fly;

import java.io.IOException;

/** Establishes the new window's ordering barrier. Only this harmless marker can be retried. */
final class HostAttachment {
    private HostAttachment() {}
    interface Barrier { void write() throws IOException; }

    static void attach(boolean running, Runnable replace, Barrier barrier) throws IOException {
        if (running) {
            try {
                barrier.write();
                return;
            } catch (IOException lostDuringAttach) {
                // The old child may exit between the liveness check and the write.
            }
        }
        replace.run();
        barrier.write();
    }
}
