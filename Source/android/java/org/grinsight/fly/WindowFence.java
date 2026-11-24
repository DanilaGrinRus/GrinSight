package org.grinsight.fly;

/** Access under windowLock. The child handles JSON-RPC calls in input order. */
final class WindowFence {
    private String waiting;
    void replace(String marker) { waiting = marker; }
    boolean waiting() { return waiting != null; }
    boolean deliver(String topLevelStringId) {
        if (waiting == null) return true;
        if (waiting.equals(topLevelStringId)) waiting = null;
        return false;
    }
}
