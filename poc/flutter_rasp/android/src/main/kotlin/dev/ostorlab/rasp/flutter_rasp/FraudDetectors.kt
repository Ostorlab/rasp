package dev.ostorlab.rasp.flutter_rasp

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.media.AudioManager
import android.os.Build
import android.view.accessibility.AccessibilityManager

/**
 * Signals that come from platform callbacks (a screenshot was taken, a touch arrived through an overlay)
 * rather than from polling. Each one stays active for [ttlMillis] so the next scans and guards see it.
 */
class TransientSignals(private val ttlMillis: Long = 5 * 60_000L, private val clock: () -> Long = System::currentTimeMillis) {
    private val signals = mutableMapOf<String, Pair<Signal, Long>>()

    @Synchronized
    fun record(signal: Signal) {
        signals[signal.detector] = signal to clock()
    }

    @Synchronized
    fun active(): List<Signal> {
        val now = clock()
        signals.entries.removeAll { now - it.value.second > ttlMillis }
        return signals.values.map { it.first }
    }
}

/** State pushed by the plugin from window callbacks. */
class ScreenState {
    @Volatile
    var recordingVisible: Boolean = false
}

/** Banking-fraud detectors: they protect a genuine user from malware and scams on their own device. */
class FraudDetectors(
    private val context: Context,
    private val config: RaspConfig,
    private val transient: TransientSignals,
    private val screen: ScreenState,
) {

    fun scan(): List<Signal> = runDetectors(
        "fraud",
        listOf(::accessibilityServices, ::remoteAccessApps, ::activeCall, ::screenMirroring, ::screenRecording, transient::active),
    )

    /**
     * Enabled accessibility services that can read the screen or perform gestures, and are not known assistive tools.
     * Banking trojans rely on these permissions to read OTPs and confirm transfers as the victim.
     */
    private fun accessibilityServices(): List<Signal> {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val suspicious = manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { info ->
                val pkg = info.resolveInfo?.serviceInfo?.packageName ?: return@mapNotNull null
                val canRead = info.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0
                val canAct = info.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES != 0
                if (isTrustedAssistiveTool(pkg) || (!canRead && !canAct)) return@mapNotNull null
                Triple(pkg, canRead, canAct)
            }
        if (suspicious.isEmpty()) {
            return emptyList()
        }
        val sideloaded = suspicious.any { (pkg, _, _) -> installerOf(pkg) !in STORE_INSTALLERS }
        val evidence = suspicious.joinToString { (pkg, canRead, canAct) ->
            "$pkg (${listOfNotNull("reads screen".takeIf { canRead }, "performs gestures".takeIf { canAct }).joinToString()}, " +
                "installer=${installerOf(pkg) ?: "none"})"
        }
        return listOf(Signal(ThreatType.ACCESSIBILITY_ABUSE, "fraud.accessibility_services", if (sideloaded) 95 else 75, evidence))
    }

    /**
     * An allowlisted package name is only trusted when the app is a system app or came from an app store: malware
     * could otherwise install itself under TalkBack's package name on a device that does not have TalkBack.
     */
    private fun isTrustedAssistiveTool(packageName: String): Boolean {
        if (packageName !in config.accessibilityAllowlist) return false
        val flags = try {
            context.packageManager.getApplicationInfo(packageName, 0).flags
        } catch (e: PackageManager.NameNotFoundException) {
            return false
        }
        val system = flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return system || installerOf(packageName) in STORE_INSTALLERS
    }

    private fun remoteAccessApps(): List<Signal> {
        val installed = REMOTE_ACCESS_PACKAGES.filter { isInstalled(it) }
        return if (installed.isEmpty()) emptyList()
        else listOf(Signal(ThreatType.REMOTE_ACCESS_APP, "fraud.remote_access_apps", 60, installed.joinToString()))
    }

    /** No permission needed: the audio mode shows a phone or VoIP call in progress. */
    private fun activeCall(): List<Signal> {
        val audio = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        val mode = audio.mode
        val inCall = mode == AudioManager.MODE_IN_CALL || mode == AudioManager.MODE_IN_COMMUNICATION ||
            (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && mode == AudioManager.MODE_CALL_SCREENING)
        return if (inCall) listOf(Signal(ThreatType.ACTIVE_CALL, "fraud.active_call", 90, "audio mode=$mode")) else emptyList()
    }

    /** Presentation displays: Cast, Miracast, or a wired external screen mirroring the app. */
    private fun screenMirroring(): List<Signal> {
        val displays = (context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager)
            .getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION)
        return if (displays.isEmpty()) emptyList()
        else listOf(Signal(ThreatType.SCREEN_MIRRORING, "fraud.presentation_display", 80, displays.joinToString { it.name }))
    }

    private fun screenRecording(): List<Signal> =
        if (screen.recordingVisible) {
            listOf(Signal(ThreatType.SCREEN_RECORDING, "fraud.screen_recording", 95, "app window is being recorded"))
        } else emptyList()

    private fun isInstalled(packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    @Suppress("DEPRECATION")
    private fun installerOf(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            context.packageManager.getInstallerPackageName(packageName)
        }
    } catch (e: Exception) {
        null
    }

    companion object {
        private val STORE_INSTALLERS = setOf("com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket")

        // Keep in sync with the <queries> block in AndroidManifest.xml.
        val REMOTE_ACCESS_PACKAGES = listOf(
            "com.anydesk.anydeskandroid", "com.teamviewer.quicksupport.market", "com.teamviewer.teamviewer.market.mobile",
            "com.carriez.flutter_hbb", "com.sand.airdroid", "com.sand.airdroidbiz", "com.splashtop.remote.pad.v2",
            "com.rsupport.mvagent", "com.logmein.rescuemobile", "com.remotepc.viewer",
        )
    }
}
