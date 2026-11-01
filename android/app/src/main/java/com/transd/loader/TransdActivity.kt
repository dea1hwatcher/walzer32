package com.transd.loader

import android.app.Activity
import android.os.Bundle
import android.view.Choreographer
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.widget.FrameLayout

/**
 * TransdActivity — SurfaceView Render Container & Event Router for Transd DBT
 */
class TransdActivity : Activity(), SurfaceHolder.Callback, Choreographer.FrameCallback {
    private lateinit var surfaceView: SurfaceView
    private var isRendering = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = FrameLayout(this)
        surfaceView = SurfaceView(this).apply {
            holder.addCallback(this@TransdActivity)
        }
        root.addView(surfaceView)
        setContentView(root)
    }

    override fun surfaceCreated(holder: SurfaceHolder) {
        val width = surfaceView.width
        val height = surfaceView.height
        TransdEngine.nativeSurfaceCreated(holder.surface, width, height)
        isRendering = true
        Choreographer.getInstance().postFrameCallback(this)
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
        TransdEngine.nativeSurfaceChanged(width, height)
    }

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        isRendering = false
        Choreographer.getInstance().removeFrameCallback(this)
        TransdEngine.nativeSurfaceDestroyed()
    }

    override fun doFrame(frameTimeNanos: Long) {
        if (isRendering) {
            TransdEngine.nativeDrawFrame()
            Choreographer.getInstance().postFrameCallback(this)
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val action = event.actionMasked
        val pointerIndex = event.actionIndex
        val pointerId = event.getPointerId(pointerIndex)
        val x = event.getX(pointerIndex)
        val y = event.getY(pointerIndex)

        TransdEngine.nativeTouchEvent(action, x, y, pointerId)
        return true
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        TransdEngine.nativeKeyEvent(KeyEvent.ACTION_DOWN, keyCode)
        return super.onKeyDown(keyCode, event)
    }

    override fun onKeyUp(keyCode: Int, event: KeyEvent?): Boolean {
        TransdEngine.nativeKeyEvent(KeyEvent.ACTION_UP, keyCode)
        return super.onKeyUp(keyCode, event)
    }
}
