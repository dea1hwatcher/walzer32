package com.transd.loader

/**
 * FramePacer — Enforces consistent frame delivery on high-refresh-rate displays (90Hz, 120Hz, 144Hz+).
 *
 * Classic 32-bit Android games often lack delta-time scaling in their game loops,
 * tying physics directly to display refresh rates. FramePacer paces rendering to
 * target 60 FPS (or configured target) to prevent games running at 2x/2.4x speed.
 */
class FramePacer(var targetFps: Int = 60) {
    private var lastFrameTimeNanos: Long = 0L

    val frameIntervalNanos: Long
        get() = if (targetFps > 0) 1_000_000_000L / targetFps else 0L

    /**
     * Evaluates whether a frame should be rendered at the given VSYNC timestamp.
     *
     * @param nowNanos Current frame timestamp from Choreographer (in nanoseconds)
     * @return true if the frame should be rendered, false if this VSYNC tick should be skipped.
     */
    fun shouldRenderFrame(nowNanos: Long): Boolean {
        if (targetFps <= 0) {
            lastFrameTimeNanos = nowNanos
            return true
        }

        val interval = frameIntervalNanos
        val elapsed = nowNanos - lastFrameTimeNanos

        // Tolerance window (10%) absorbs minor hardware VSYNC jitter
        val jitterTolerance = interval / 10
        if (elapsed >= interval - jitterTolerance) {
            if (lastFrameTimeNanos == 0L || elapsed > interval * 2) {
                lastFrameTimeNanos = nowNanos
            } else {
                lastFrameTimeNanos += interval
            }
            return true
        }

        return false
    }

    /**
     * Resets the pacing state (e.g. when resuming or surface is recreated).
     */
    fun reset() {
        lastFrameTimeNanos = 0L
    }
}
