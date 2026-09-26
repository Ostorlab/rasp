package dev.ostorlab.rasp.flutter_rasp

import android.app.Activity
import android.os.Build
import android.view.KeyboardShortcutGroup
import android.view.Menu
import android.view.MotionEvent
import android.view.View
import android.view.Window
import android.view.WindowManager
import androidx.annotation.RequiresApi
import java.util.function.Consumer

/**
 * Window-level protections for one activity:
 * - secure mode: FLAG_SECURE (no screenshots or recordings of the window);
 * - sensitive mode (PIN, transfer screens): secure mode, plus hiding other apps' overlays, dropping touches that
 *   pass through an overlay (tapjacking), and hiding content from accessibility services that are not assistive tools;
 * - screenshot (Android 14+) and screen-recording (Android 15+) callbacks, reported as fraud signals.
 */
class ScreenProtector(
    private val activity: Activity,
    private val onSignal: (Signal) -> Unit,
    private val onRecordingChanged: (Boolean) -> Unit,
) {
    private var secure = false
    private var sensitive = false
    private var policySecure = false
    private var screenshotCallback: Any? = null
    private var recordingCallback: Any? = null
    private var originalCallback: Window.Callback? = null

    fun attach() {
        val window = activity.window
        originalCallback = window.callback
        window.callback = TouchObserver(window.callback, ::onTouch)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) registerScreenshotCallback()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) registerRecordingCallback()
        apply()
    }

    fun detach() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) unregisterScreenshotCallback()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) unregisterRecordingCallback()
        originalCallback?.let { activity.window.callback = it }
        originalCallback = null
    }

    fun setSecure(enabled: Boolean) {
        secure = enabled
        apply()
    }

    fun setSensitive(enabled: Boolean) {
        sensitive = enabled
        apply()
    }

    /** Set by the policy when an active threat has the secureScreen reaction. */
    fun setPolicySecure(enabled: Boolean) {
        policySecure = enabled
        apply()
    }

    private fun apply() {
        val window = activity.window
        if (secure || sensitive || policySecure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(sensitive)
        }
        val decor = window.decorView
        decor.filterTouchesWhenObscured = sensitive
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            decor.setAccessibilityDataSensitive(
                if (sensitive) View.ACCESSIBILITY_DATA_SENSITIVE_YES else View.ACCESSIBILITY_DATA_SENSITIVE_AUTO,
            )
        }
    }

    private fun onTouch(event: MotionEvent) {
        if (!sensitive || event.actionMasked != MotionEvent.ACTION_DOWN) return
        val obscured = event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0
        val partially = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
        if (obscured || partially) {
            onSignal(
                Signal(
                    ThreatType.OVERLAY, "fraud.obscured_touch", 90,
                    if (obscured) "touch through a full overlay" else "touch through a partial overlay",
                ),
            )
        }
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun registerScreenshotCallback() {
        val callback = Activity.ScreenCaptureCallback {
            onSignal(Signal(ThreatType.SCREEN_CAPTURE, "fraud.screenshot", 100, "screenshot taken of ${activity.localClassName}"))
        }
        activity.registerScreenCaptureCallback(activity.mainExecutor, callback)
        screenshotCallback = callback
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun unregisterScreenshotCallback() {
        (screenshotCallback as? Activity.ScreenCaptureCallback)?.let { activity.unregisterScreenCaptureCallback(it) }
        screenshotCallback = null
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    private fun registerRecordingCallback() {
        val callback = Consumer<Int> { state -> onRecordingChanged(state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE) }
        // The callback only fires on changes, so the returned initial state matters.
        val initial = activity.windowManager.addScreenRecordingCallback(activity.mainExecutor, callback)
        recordingCallback = callback
        onRecordingChanged(initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    private fun unregisterRecordingCallback() {
        @Suppress("UNCHECKED_CAST")
        (recordingCallback as? Consumer<Int>)?.let { activity.windowManager.removeScreenRecordingCallback(it) }
        recordingCallback = null
    }
}

/** Forwards everything to the activity's own callback and lets us observe touches first. */
private class TouchObserver(
    private val delegate: Window.Callback,
    private val onTouch: (MotionEvent) -> Unit,
) : Window.Callback by delegate {

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        onTouch(event)
        return delegate.dispatchTouchEvent(event)
    }

    // Java default methods are not covered by Kotlin delegation; forward them explicitly.
    override fun onProvideKeyboardShortcuts(data: MutableList<KeyboardShortcutGroup>?, menu: Menu?, deviceId: Int) =
        delegate.onProvideKeyboardShortcuts(data, menu, deviceId)

    override fun onPointerCaptureChanged(hasCapture: Boolean) = delegate.onPointerCaptureChanged(hasCapture)
}
