package io.mosip.openID4VP.browser

import io.mosip.openID4VP.verifier.VerifierResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BrowserRedirectHandlerTest {

    private class FakeBrowserPlatform(
        private val browsers: List<BrowserApp> = emptyList(),
        private val openSucceeds: Boolean = true
    ) : BrowserPlatform {
        var openCallCount = 0
        var openedRedirectUri: String? = null
        var openedBrowser: BrowserApp? = null
        var openedAsBrowserNavigable: Boolean? = null

        override fun queryBrowsers(): List<BrowserApp> = browsers

        override fun open(
            redirectUri: String,
            browser: BrowserApp?,
            browserNavigable: Boolean
        ): Boolean {
            openCallCount++
            openedRedirectUri = redirectUri
            openedBrowser = browser
            openedAsBrowserNavigable = browserNavigable
            return openSucceeds
        }
    }

    private fun browser(
        packageName: String,
        displayName: String,
        isDefault: Boolean = false
    ) = BrowserApp(
        packageName = packageName,
        activityName = "$packageName.MainActivity",
        displayName = displayName,
        isDefault = isDefault
    )

    private fun verifierResponse(redirectUri: String?) = VerifierResponse(
        statusCode = 200,
        redirectUri = redirectUri,
        additionalParams = null,
        headers = emptyMap()
    )

    private val redirectUri =
        "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"

    @Test
    fun `should list the default browser first and order the rest by display name`() {
        val platform = FakeBrowserPlatform(
            listOf(
                browser("org.mozilla.firefox", "Firefox"),
                browser("com.brave.browser", "Brave"),
                browser("com.android.chrome", "Chrome", isDefault = true)
            )
        )

        val browsers = BrowserRedirectHandler(platform).getAvailableBrowsers()

        assertEquals(
            listOf("com.android.chrome", "com.brave.browser", "org.mozilla.firefox"),
            browsers.map { it.packageName }
        )
        assertTrue(browsers.first().isDefault)
    }

    @Test
    fun `should not list the same browser package twice`() {
        val platform = FakeBrowserPlatform(
            listOf(
                browser("com.android.chrome", "Chrome"),
                browser("com.android.chrome", "Chrome")
            )
        )

        assertEquals(1, BrowserRedirectHandler(platform).getAvailableBrowsers().size)
    }

    @Test
    fun `should return no browsers when the package manager reports none`() {
        assertTrue(BrowserRedirectHandler(FakeBrowserPlatform()).getAvailableBrowsers().isEmpty())
    }

    @Test
    fun `should redirect to the redirect uri returned by the verifier`() {
        val platform = FakeBrowserPlatform()

        val redirected = BrowserRedirectHandler(platform).redirect(verifierResponse(redirectUri))

        assertTrue(redirected)
        assertEquals(1, platform.openCallCount)
        assertEquals(redirectUri, platform.openedRedirectUri)
        assertEquals(true, platform.openedAsBrowserNavigable)
    }

    @Test
    fun `should open the redirect uri in the browser chosen by the end user`() {
        val platform = FakeBrowserPlatform()
        val chosenBrowser = browser("org.mozilla.firefox", "Firefox")

        val redirected =
            BrowserRedirectHandler(platform).redirect(verifierResponse(redirectUri), chosenBrowser)

        assertTrue(redirected)
        assertEquals(chosenBrowser, platform.openedBrowser)
    }

    @Test
    fun `should not redirect when the verifier response has no redirect uri`() {
        val platform = FakeBrowserPlatform()
        val handler = BrowserRedirectHandler(platform)

        assertFalse(handler.redirect(verifierResponse(null)))
        assertFalse(handler.redirect(verifierResponse("")))
        assertFalse(handler.redirect(null as VerifierResponse?))
        assertEquals(0, platform.openCallCount)
    }

    @Test
    fun `should not redirect when the redirect uri is malformed or relative`() {
        val platform = FakeBrowserPlatform()
        val handler = BrowserRedirectHandler(platform)

        listOf("/cb?response_code=123", "https://verifier.example.com/a b", "https:///cb")
            .forEach { assertFalse(handler.redirect(verifierResponse(it)), "expected $it to be skipped") }

        assertEquals(0, platform.openCallCount)
    }

    @Test
    fun `should report failure when no application could open the redirect uri`() {
        val platform = FakeBrowserPlatform(openSucceeds = false)

        assertFalse(BrowserRedirectHandler(platform).redirect(verifierResponse(redirectUri)))
        assertEquals(1, platform.openCallCount)
    }

    @Test
    fun `should let the platform resolve a handler for a non http redirect uri`() {
        val platform = FakeBrowserPlatform()
        val appLink = "mywallet://verifier-callback?response_code=123"

        val redirected = BrowserRedirectHandler(platform)
            .redirect(verifierResponse(appLink), browser("com.android.chrome", "Chrome"))

        assertTrue(redirected)
        assertEquals(appLink, platform.openedRedirectUri)
        assertEquals(false, platform.openedAsBrowserNavigable)
        assertNull(platform.openedBrowser)
    }

    @Test
    fun `should report whether the verifier response can be redirected to`() {
        val handler = BrowserRedirectHandler(FakeBrowserPlatform())

        assertTrue(handler.canRedirect(verifierResponse(redirectUri)))
        assertTrue(handler.canRedirect(verifierResponse("mywallet://callback")))
        assertFalse(handler.canRedirect(verifierResponse(null)))
        assertFalse(handler.canRedirect(verifierResponse("/relative")))
    }

    @Test
    fun `should offer a browser choice only for http redirect uris`() {
        val handler = BrowserRedirectHandler(FakeBrowserPlatform())

        assertTrue(handler.shouldOfferBrowserChoice(verifierResponse(redirectUri)))
        assertFalse(handler.shouldOfferBrowserChoice(verifierResponse("mywallet://callback")))
        assertFalse(handler.shouldOfferBrowserChoice(verifierResponse(null)))
    }
}
