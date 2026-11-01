package com.transd.loader

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/**
 * TransdActivity — Launcher / Diagnostic Activity for Transd DBT
 */
class TransdActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val status = TransdEngine.nativeGetStatus()
        val textView = TextView(this).apply {
            text = "Transd DBT Engine Active\nLoaded 32-bit Libraries: $status\nDevice ABI: ${android.os.Build.SUPPORTED_ABIS.firstOrNull()}"
            textSize = 18f
            setPadding(32, 64, 32, 64)
        }
        setContentView(textView)
    }
}
