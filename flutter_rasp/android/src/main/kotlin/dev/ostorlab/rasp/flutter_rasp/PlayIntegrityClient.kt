package dev.ostorlab.rasp.flutter_rasp

import android.content.Context
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import java.util.concurrent.TimeUnit

/** Call on a worker thread. Tokens are opaque and verified by Google through the trust service. */
class PlayIntegrityClient(context: Context) {
    private val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
    private var project: Long? = null
    private var provider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    @Synchronized fun token(nonce: String, cloudProjectNumber: Long): String {
        require(nonce.isNotEmpty() && nonce.length <= 1024 && cloudProjectNumber > 0)
        if (provider == null || project != cloudProjectNumber) {
            provider = Tasks.await(manager.prepareIntegrityToken(
                StandardIntegrityManager.PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build()),
                60, TimeUnit.SECONDS)
            project = cloudProjectNumber
        }
        return try {
            Tasks.await(provider!!.request(StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                .setRequestHash(TrustCrypto.b64Url(TrustCrypto.sha256(nonce.toByteArray(Charsets.UTF_8)))).build()),
                60, TimeUnit.SECONDS).token()
        } catch (error: Exception) {
            // Invalid providers are not reused; the next explicit request warms a fresh provider.
            provider = null
            throw error
        }
    }
}
