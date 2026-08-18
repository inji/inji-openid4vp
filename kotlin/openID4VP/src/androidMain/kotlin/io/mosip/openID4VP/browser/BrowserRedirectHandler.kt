package io.mosip.openID4VP.browser

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import io.mosip.openID4VP.common.BuildConfig.getVersionSDKInt
import io.mosip.openID4VP.common.isBrowserNavigableRedirectUri
import io.mosip.openID4VP.common.isNavigableRedirectUri
import io.mosip.openID4VP.common.sanitizeRedirectUri
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.verifier.VerifierResponse

data class BrowserApp(
    val packageName: String,
    val activityName: String,
    val displayName: String,
    val isDefault: Boolean = false
)

class BrowserRedirectHandler internal constructor(private val platform: BrowserPlatform) {

    constructor(context: Context) : this(AndroidBrowserPlatform(context.applicationContext))

    fun getAvailableBrowsers(): List<BrowserApp> =
        platform.queryBrowsers()
            .distinctBy { it.packageName }
            .sortedWith(
                compareByDescending<BrowserApp> { it.isDefault }
                    .thenBy { it.displayName.lowercase() }
            )

    fun canRedirect(verifierResponse: VerifierResponse?): Boolean =
        canRedirect(verifierResponse?.redirectUri)

    fun canRedirect(redirectUri: String?): Boolean = isNavigableRedirectUri(redirectUri)

    fun shouldOfferBrowserChoice(verifierResponse: VerifierResponse?): Boolean =
        isBrowserNavigableRedirectUri(verifierResponse?.redirectUri)

    @JvmOverloads
    fun redirect(verifierResponse: VerifierResponse?, browser: BrowserApp? = null): Boolean =
        redirect(verifierResponse?.redirectUri, browser)

    @JvmOverloads
    fun redirect(redirectUri: String?, browser: BrowserApp? = null): Boolean {
        val sanitizedRedirectUri = sanitizeRedirectUri(redirectUri)
        if (sanitizedRedirectUri == null) {
            if (!redirectUri.isNullOrBlank()) {
                OpenID4VPExceptions.error(
                    "Verifier returned a redirect_uri that is not an absolute navigable URI. Redirection is skipped.",
                    className
                )
            }
            return false
        }

        val browserNavigable = isBrowserNavigableRedirectUri(sanitizedRedirectUri)
        val launched = platform.open(
            redirectUri = sanitizedRedirectUri,
            browser = browser?.takeIf { browserNavigable },
            browserNavigable = browserNavigable
        )

        if (!launched) {
            OpenID4VPExceptions.error(
                "No application on the device was able to open the redirect_uri returned by the Verifier.",
                className
            )
        }
        return launched
    }

    private companion object {
        private val className = BrowserRedirectHandler::class.simpleName.orEmpty()
    }
}

internal interface BrowserPlatform {
    fun queryBrowsers(): List<BrowserApp>

    fun open(redirectUri: String, browser: BrowserApp?, browserNavigable: Boolean): Boolean
}

internal class AndroidBrowserPlatform(private val context: Context) : BrowserPlatform {

    override fun queryBrowsers(): List<BrowserApp> {
        val packageManager = context.packageManager ?: return emptyList()
        val probeIntent = browsableProbeIntent()

        val defaultBrowserPackage = runCatching {
            resolveActivityCompat(packageManager, probeIntent)?.activityInfo?.packageName
        }.getOrNull()

        return runCatching { queryIntentActivitiesCompat(packageManager, probeIntent) }
            .getOrDefault(emptyList())
            .mapNotNull { resolveInfo ->
                val activityInfo = resolveInfo.activityInfo ?: return@mapNotNull null
                BrowserApp(
                    packageName = activityInfo.packageName,
                    activityName = activityInfo.name,
                    displayName = resolveInfo.displayName(packageManager, activityInfo.packageName),
                    isDefault = activityInfo.packageName == defaultBrowserPackage
                )
            }
    }

    override fun open(
        redirectUri: String,
        browser: BrowserApp?,
        browserNavigable: Boolean
    ): Boolean {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(redirectUri)).apply {
            if (browserNavigable) addCategory(Intent.CATEGORY_BROWSABLE)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            browser?.let { setClassName(it.packageName, it.activityName) }
        }

        return runCatching {
            context.startActivity(intent)
            true
        }.getOrElse { false }
    }

    private fun browsableProbeIntent(): Intent =
        Intent()
            .setAction(Intent.ACTION_VIEW)
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setData(Uri.fromParts("http", "", null))

    private fun ResolveInfo.displayName(
        packageManager: PackageManager,
        fallback: String
    ): String = runCatching { loadLabel(packageManager).toString() }
        .getOrNull()
        ?.takeIf { it.isNotBlank() }
        ?: fallback

    private fun queryIntentActivitiesCompat(
        packageManager: PackageManager,
        intent: Intent
    ): List<ResolveInfo> =
        if (getVersionSDKInt() >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(
                intent,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        }

    private fun resolveActivityCompat(
        packageManager: PackageManager,
        intent: Intent
    ): ResolveInfo? =
        if (getVersionSDKInt() >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.resolveActivity(
                intent,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }
}
