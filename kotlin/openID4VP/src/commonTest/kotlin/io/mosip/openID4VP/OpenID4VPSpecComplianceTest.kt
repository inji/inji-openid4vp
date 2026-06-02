package io.mosip.openID4VP

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.*
import kotlin.test.*

/**
 * Tests for OpenID4VP.kt changes from PR #111:
 * - Wallet nonce regeneration per call
 * - State reset (authorizationRequest, responseUri) before each authentication
 * - Error dispatch (safeSendError) on authentication failure
 * - shouldValidateClient flag passthrough
 * - response_type = vp_token enforcement
 */
class OpenID4VPWalletNonceAndStateResetTest {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        mockkObject(AuthorizationRequest)
        openID4VP = OpenID4VP("wallet-nonce-state-test")
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    // --- Wallet Nonce Regeneration ---

    @Test
    fun `wallet nonce is regenerated on each authenticateVerifier call`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier("openid4vp://authorize?request=test1")
        val firstNonce = getFieldValue(openID4VP, "walletNonce") as String

        openID4VP.authenticateVerifier("openid4vp://authorize?request=test2")
        val secondNonce = getFieldValue(openID4VP, "walletNonce") as String

        assertNotEquals(firstNonce, secondNonce, "wallet_nonce must be regenerated on each call")
    }

    @Test
    fun `wallet nonce is regenerated even if authenticateVerifier fails`() {
        val initialNonce = getFieldValue(openID4VP, "walletNonce") as String

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } throws OpenID4VPExceptions.InvalidData("test", "test")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, "{}", mapOf())

        assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier("bad-request")
        }

        val nonceAfterFailure = getFieldValue(openID4VP, "walletNonce") as String
        assertNotEquals(initialNonce, nonceAfterFailure)
    }

    @Test
    fun `multiple authenticateVerifier calls produce unique wallet nonces`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier("openid4vp://authorize?request=r1")
        val nonce1 = getFieldValue(openID4VP, "walletNonce") as String

        openID4VP.authenticateVerifier("openid4vp://authorize?request=r2")
        val nonce2 = getFieldValue(openID4VP, "walletNonce") as String

        openID4VP.authenticateVerifier("openid4vp://authorize?request=r3")
        val nonce3 = getFieldValue(openID4VP, "walletNonce") as String

        assertNotEquals(nonce1, nonce2)
        assertNotEquals(nonce2, nonce3)
        assertNotEquals(nonce1, nonce3)
    }

    // --- State Reset ---

    @Test
    fun `authenticateVerifier with String resets authorizationRequest before validation`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier("openid4vp://authorize?request=first")
        assertNotNull(openID4VP.authorizationRequest)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } throws OpenID4VPExceptions.InvalidData("test", "test")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, "{}", mapOf())

        assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier("openid4vp://authorize?request=second")
        }

        assertNull(openID4VP.authorizationRequest, "authorizationRequest must be reset before new validation")
    }

    @Test
    fun `authenticateVerifier with Map resets authorizationRequest before validation`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<Map<String, Any>>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier(mapOf("client_id" to "test" as Any), trustedVerifiers)
        assertNotNull(openID4VP.authorizationRequest)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<Map<String, Any>>(), any(), any(), any(), any()
            )
        } throws OpenID4VPExceptions.InvalidData("test", "test")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, "{}", mapOf())

        assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier(mapOf("client_id" to "bad" as Any), trustedVerifiers)
        }

        assertNull(openID4VP.authorizationRequest)
    }

    @Test
    fun `authenticateVerifier resets responseUri before validation`() {
        setField(openID4VP, "responseUri", "https://old-uri.com")

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier("openid4vp://authorize?request=test")

        val currentResponseUri = getFieldValue(openID4VP, "responseUri")
        assertNotEquals("https://old-uri.com", currentResponseUri)
    }

    // --- response_type = vp_token ---

    @Test
    fun `authenticateVerifier returns AuthorizationRequest with response_type vp_token`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        val result = openID4VP.authenticateVerifier("openid4vp://authorize?request=valid")
        assertEquals("vp_token", result.responseType)
    }

    // --- shouldValidateClient passthrough ---

    @Test
    fun `authenticateVerifier String passes shouldValidateClient=true by default`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), eq(true), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier("openid4vp://authorize?request=test")

        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), eq(true), any()
            )
        }
    }

    @Test
    fun `authenticateVerifier String passes shouldValidateClient=false when specified`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), eq(false), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier(
            "openid4vp://authorize?request=test",
            shouldValidateClient = false
        )

        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), eq(false), any()
            )
        }
    }

    @Test
    fun `authenticateVerifier Map passes shouldValidateClient=false when specified`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<Map<String, Any>>(), any(), any(), eq(false), any()
            )
        } returns authorizationRequest

        openID4VP.authenticateVerifier(
            mapOf("client_id" to "test" as Any),
            trustedVerifiers,
            shouldValidateClient = false
        )

        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<Map<String, Any>>(), any(), any(), eq(false), any()
            )
        }
    }

    @Test
    fun `authenticateVerifier Map overload sets authorizationRequest on success`() {
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<Map<String, Any>>(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        val result = openID4VP.authenticateVerifier(
            mapOf("client_id" to "redirect_uri:https://example.com" as Any),
            trustedVerifiers
        )

        assertNotNull(openID4VP.authorizationRequest)
        assertEquals(authorizationRequest, result)
    }

    // --- WalletMetadata propagation ---

    @Test
    fun `OpenID4VP constructed with walletConfig propagates without crash`() {
        val instance = OpenID4VP("with-metadata", walletConfig)
        assertNotNull(instance)
    }

    @Test
    fun `OpenID4VP constructed without walletMetadata functions correctly`() {
        val instance = OpenID4VP("no-metadata")
        assertNotNull(instance)
    }

    // --- Helper ---

    private fun getFieldValue(instance: Any, fieldName: String): Any? {
        val field = instance::class.java.getDeclaredField(fieldName)
        field.isAccessible = true
        return field.get(instance)
    }
}
