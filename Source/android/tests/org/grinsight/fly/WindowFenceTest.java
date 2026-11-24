package org.grinsight.fly;

/** Offline contract: two local windows are allowed to use the same numeric RPC id. */
public final class WindowFenceTest {
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    public static void main(String[] args) {
        WindowFence gate = new WindowFence();
        gate.replace("A");
        gate.deliver("A");
        gate.replace("B");
        check(!gate.deliver(null));  // delayed normal answer for A
        gate.replace("C");           // B disconnects before its barrier
        check(!gate.deliver("B"));
        check(!gate.deliver(null));
        check(!gate.deliver("C"));   // the internal receipt is consumed locally
        check(gate.deliver(null));   // the next normal answer is for C
        System.out.println("window replacement and overlapping barriers: passed");
    }
}
