package xyz.cirno.avbsign;

import java.util.TreeMap;

final class OperationState {
    private final StringBuilder log = new StringBuilder();
    private final TreeMap<Long, String> pendingLogs = new TreeMap<>();
    private boolean started;
    private boolean finished;
    private long nextSequence = 1;
    private long lastSequence = -1;
    private String pendingResult;

    boolean start() {
        if (started) {
            return false;
        }
        started = true;
        return true;
    }

    void append(String message) {
        log.append(message).append('\n');
    }

    void appendLog(long sequence, String message) {
        if (finished) {
            return;
        }
        if (sequence < nextSequence || (lastSequence >= 0 && sequence > lastSequence)
                || pendingLogs.putIfAbsent(sequence, message) != null) {
            throw new IllegalArgumentException("重复或无效的日志序号：" + sequence);
        }
        while (pendingLogs.containsKey(nextSequence)) {
            append(pendingLogs.remove(nextSequence++));
        }
        finishIfReady();
    }

    void finishAfterLogs(long lastSequence, String result) {
        if (lastSequence < nextSequence - 1
                || (!pendingLogs.isEmpty() && pendingLogs.lastKey() > lastSequence)) {
            throw new IllegalArgumentException("无效的最后日志序号：" + lastSequence);
        }
        this.lastSequence = lastSequence;
        pendingResult = result;
        finishIfReady();
    }

    private void finishIfReady() {
        if (lastSequence >= 0 && nextSequence > lastSequence) {
            complete(pendingResult);
        }
    }

    void complete(String result) {
        append(result);
        finished = true;
    }

    boolean isFinished() {
        return finished;
    }

    String log() {
        return log.toString();
    }
}
