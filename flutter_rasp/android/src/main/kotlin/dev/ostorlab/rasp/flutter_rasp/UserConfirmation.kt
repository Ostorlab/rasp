package dev.ostorlab.rasp.flutter_rasp

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import java.security.Signature
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

class UserConfirmationException(val code: String, message: String) : Exception(message)

/**
 * Shows the system BiometricPrompt for a user-auth-bound key. The prompt is drawn by the system, not the app, and
 * the text shows what is being signed (e.g. "Send $50.00 to Alex Smith").
 */
object UserConfirmation {

    /** Blocks the calling (background) thread until the user confirms or cancels. Must not run on the UI thread. */
    fun authorize(activity: Activity, signature: Signature, title: String, description: String): Signature {
        val result = CompletableFuture<Signature>()
        activity.runOnUiThread {
            try {
                show(activity, signature, title, description, result)
            } catch (e: Exception) {
                // Never let a prompt failure crash the app from the UI thread; fail the signing call instead.
                result.completeExceptionally(UserConfirmationException("auth_failed", e.message ?: e.javaClass.simpleName))
            }
        }
        return try {
            result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        } catch (e: TimeoutException) {
            throw UserConfirmationException("auth_timeout", "no answer within $TIMEOUT_SECONDS s")
        }
    }

    private fun show(
        activity: Activity,
        signature: Signature,
        title: String,
        description: String,
        result: CompletableFuture<Signature>,
    ) {
        val builder = BiometricPrompt.Builder(activity).setTitle(title).setDescription(description)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
        } else {
            builder.setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                result.completeExceptionally(UserConfirmationException("auth_cancelled", "cancelled"))
            }
        }
        builder.build().authenticate(
            BiometricPrompt.CryptoObject(signature),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                    val authorized = auth.cryptoObject?.signature
                    if (authorized == null) {
                        result.completeExceptionally(UserConfirmationException("auth_failed", "no signature returned"))
                    } else {
                        result.complete(authorized)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                    result.completeExceptionally(
                        UserConfirmationException(if (cancelled) "auth_cancelled" else "auth_failed", errString.toString()),
                    )
                }
            },
        )
    }

    private const val TIMEOUT_SECONDS = 120L
}
