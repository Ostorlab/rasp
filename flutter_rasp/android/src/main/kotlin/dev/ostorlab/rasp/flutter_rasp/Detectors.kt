package dev.ostorlab.rasp.flutter_rasp

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.util.Log
import org.json.JSONArray
import java.security.MessageDigest

/** Bridge to librasp_core.so. */
object NativeDetectors {
    private const val TAG = "flutter_rasp"

    private val loaded: Boolean = try {
        System.loadLibrary("rasp_core")
        true
    } catch (e: UnsatisfiedLinkError) {
        Log.w(TAG, "native core unavailable", e)
        false
    }

    @JvmStatic
    private external fun nativeScan(): String

    fun scan(): List<Signal> {
        if (!loaded) {
            return emptyList()
        }
        val array = JSONArray(nativeScan())
        return (0 until array.length()).mapNotNull { i ->
            val item = array.getJSONObject(i)
            ThreatType.fromNative(item.getInt("threat"))?.let { threat ->
                Signal(threat, item.getString("detector"), item.getInt("confidence"), item.getString("evidence"))
            }
        }
    }
}

/** Detectors that need Android framework APIs. Each returns zero or more signals and never throws. */
class PlatformDetectors(private val context: Context, private val config: RaspConfig) {

    fun scan(): List<Signal> = listOf(
        ::rootPackages, ::buildTags, ::emulatorBuild, ::debugger, ::hookingFramework,
        ::signingCertificate, ::packageName, ::debuggableFlag, ::installer, ::deviceSettings,
    ).flatMap { detector ->
        try {
            detector()
        } catch (e: Exception) {
            Log.w("flutter_rasp", "detector failed", e)
            emptyList()
        }
    }

    private fun rootPackages(): List<Signal> {
        val installed = ROOT_PACKAGES.filter { isInstalled(it) }
        return if (installed.isEmpty()) emptyList()
        else listOf(Signal(ThreatType.ROOT, "platform.root_packages", 80, installed.joinToString()))
    }

    private fun buildTags(): List<Signal> =
        if (Build.TAGS?.contains("test-keys") == true) {
            listOf(Signal(ThreatType.ROOT, "platform.test_keys", 50, "Build.TAGS=${Build.TAGS}"))
        } else emptyList()

    private fun emulatorBuild(): List<Signal> {
        val hints = buildList {
            if (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.contains("emulator")) add("fingerprint")
            if (EMULATOR_MODELS.any { Build.MODEL.contains(it, ignoreCase = true) }) add("model=${Build.MODEL}")
            if (Build.HARDWARE in setOf("goldfish", "ranchu")) add("hardware=${Build.HARDWARE}")
            if (Build.PRODUCT.startsWith("sdk") || Build.PRODUCT.contains("emulator")) add("product=${Build.PRODUCT}")
            if (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) add("generic brand/device")
        }
        return if (hints.isEmpty()) emptyList()
        else listOf(Signal(ThreatType.EMULATOR, "platform.emulator_build", (40 + hints.size * 15).coerceAtMost(95), hints.joinToString()))
    }

    private fun debugger(): List<Signal> =
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            listOf(Signal(ThreatType.DEBUGGER, "platform.debugger_connected", 95, "JDWP debugger attached"))
        } else emptyList()

    private fun hookingFramework(): List<Signal> {
        val signals = mutableListOf<Signal>()
        val xposedClass = HOOK_CLASSES.firstOrNull { name ->
            try {
                Class.forName(name, false, ClassLoader.getSystemClassLoader())
                true
            } catch (e: ClassNotFoundException) {
                false
            }
        }
        if (xposedClass != null) {
            signals += Signal(ThreatType.HOOKING, "platform.hook_classes", 90, xposedClass)
        }
        val frame = Throwable().stackTrace.firstOrNull { el -> HOOK_FRAMES.any { el.className.contains(it) } }
        if (frame != null) {
            signals += Signal(ThreatType.HOOKING, "platform.hook_stack", 90, frame.className)
        }
        return signals
    }

    private fun signingCertificate(): List<Signal> {
        if (config.expectedSigningCertSha256.isEmpty()) {
            return emptyList()
        }
        val actual = signingCertDigests()
        return if (actual.isNotEmpty() && actual.all { it in config.expectedSigningCertSha256 }) emptyList()
        else listOf(Signal(ThreatType.TAMPER, "platform.signing_cert", 95, "sha256=${actual.joinToString()}"))
    }

    private fun packageName(): List<Signal> {
        val expected = config.expectedPackageName ?: return emptyList()
        return if (context.packageName == expected) emptyList()
        else listOf(Signal(ThreatType.TAMPER, "platform.package_name", 90, context.packageName))
    }

    private fun debuggableFlag(): List<Signal> {
        // A release build that became debuggable was most likely repackaged. Skipped in dev mode, where it is expected.
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        return if (debuggable && !config.devMode) {
            listOf(Signal(ThreatType.TAMPER, "platform.debuggable_flag", 70, "android:debuggable=true"))
        } else emptyList()
    }

    private fun installer(): List<Signal> {
        if (config.allowedInstallers.isEmpty()) {
            return emptyList()
        }
        val installer = installerPackage()
        return if (installer in config.allowedInstallers) emptyList()
        else listOf(Signal(ThreatType.UNTRUSTED_INSTALLER, "platform.installer", 60, installer ?: "none (sideloaded)"))
    }

    private fun deviceSettings(): List<Signal> {
        val resolver = context.contentResolver
        val signals = mutableListOf<Signal>()
        if (Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1) {
            signals += Signal(ThreatType.DEV_OPTIONS, "platform.dev_options", 100, "developer options enabled")
        }
        if (Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1) {
            signals += Signal(ThreatType.ADB_ENABLED, "platform.adb_enabled", 100, "USB debugging enabled")
        }
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isDeviceSecure) {
            signals += Signal(ThreatType.NO_SCREEN_LOCK, "platform.screen_lock", 100, "no PIN, pattern or password")
        }
        return signals
    }

    private fun isInstalled(packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    @Suppress("DEPRECATION")
    private fun signingCertDigests(): List<String> {
        val pm = context.packageManager
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signingInfo = info.signingInfo ?: return emptyList()
            if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
        } else {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
        }
        return signatures.orEmpty().map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }

    @Suppress("DEPRECATION")
    private fun installerPackage(): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            context.packageManager.getInstallerPackageName(context.packageName)
        }

    companion object {
        // Keep in sync with the <queries> block in AndroidManifest.xml.
        val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk", "io.github.huskydg.magisk", "me.weishu.kernelsu", "me.bmax.apatch",
            "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.noshufou.android.su",
            "org.lsposed.manager", "de.robv.android.xposed.installer",
        )
        private val EMULATOR_MODELS = listOf("google_sdk", "Emulator", "Android SDK built for", "sdk_gphone")
        private val HOOK_CLASSES = listOf("de.robv.android.xposed.XposedBridge", "de.robv.android.xposed.XposedHelpers")
        private val HOOK_FRAMES = listOf("de.robv.android.xposed", "LSPHooker", "com.saurik.substrate")
    }
}
