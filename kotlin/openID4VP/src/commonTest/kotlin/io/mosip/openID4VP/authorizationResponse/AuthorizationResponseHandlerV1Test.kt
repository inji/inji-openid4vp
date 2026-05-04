package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mockk.*
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.verifier.VerifierResponse
import kotlin.test.*

/**
 * Tests for AuthorizationResponseHandler.kt changes from PR #111:
 * - constructUnsignedVPToken passes walletNonce
 * - constructVPResponse returns error map on failure instead of throwing
 * - sendVPResponseToVerifier returns VerifierResponse with redirect_uri
 * - constructErrorInfo produces spec-compliant structure
 */
class AuthorizationResponseHandlerV1Test {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        mockkObject(AuthorizationRequest)
        openID4VP = OpenID4VP("response-handler-v1-test")
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)
        setField(openID4VP, "walletNonce", "test-wallet-nonce")
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    // --- constructUnsignedVPToken passes walletNonce ---

    @Test
    fun `constructUnsignedVPToken passes walletNonce for KB-JWT and proof challenge`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any(), eq("test-wallet-nonce"))
        } returns emptyList()

        openID4VP.constructUnsignedVPToken(emptyMap(), holderId, signatureSuite)

        verify {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any(), eq("test-wallet-nonce"))
        }
    }

    @Test
    fun `constructUnsignedVPToken sends error to verifier on OpenID4VPException`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any(), any())
        } throws OpenID4VPExceptions.InvalidData("No credentials", "test")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, """{"ok":true}""", mapOf())

        val thrown = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.constructUnsignedVPToken(emptyMap(), holderId, signatureSuite)
        }
        assertEquals("No credentials", thrown.message)
    }

    // --- constructVPResponse error map fallback ---

    @Test
    fun `constructVPResponse returns error map on OpenID4VPExceptions instead of throwing`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructVPResponse(any(), any())
        } throws OpenID4VPExceptions.InvalidData("bad signing result", "test")

        every {
            mockHandler.constructAuthorizationErrorResponse(any(), any(), any())
        } returns mapOf("error" to "invalid_request", "error_description" to "bad signing result")

        val result = openID4VP.constructVPResponse(emptyList())

        assertEquals("invalid_request", result["error"])
        assertEquals("bad signing result", result["error_description"])
    }

    @Test
    fun `constructVPResponse returns vp_token and presentation_submission on success`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructVPResponse(any(), any())
        } returns mapOf(
            "vp_token" to "signed-vp-token",
            "presentation_submission" to "{...}",
            "state" to "some-state"
        )

        val result = openID4VP.constructVPResponse(emptyList())

        assertTrue(result.containsKey("vp_token"))
        assertTrue(result.containsKey("presentation_submission"))
    }

    // --- sendVPResponseToVerifier ---

    @Test
    fun `sendVPResponseToVerifier returns VerifierResponse with redirect_uri`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(
            200,
            "https://verifier.com/redirect#response_code=abc",
            """{"transaction_id":"123"}""",
            mapOf("Content-Type" to listOf("application/json"))
        )

        val result = openID4VP.sendVPResponseToVerifier(emptyList())

        assertEquals(200, result.statusCode)
        assertEquals("https://verifier.com/redirect#response_code=abc", result.redirectUri)
        assertEquals("""{"transaction_id":"123"}""", result.additionalParams)
    }

    @Test
    fun `sendVPResponseToVerifier handles null redirect_uri from verifier`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(200, null, """{"tx_id":"abc"}""", mapOf())

        val result = openID4VP.sendVPResponseToVerifier(emptyList())

        assertNull(result.redirectUri)
        assertEquals("""{"tx_id":"abc"}""", result.additionalParams)
    }

    @Test
    fun `sendVPResponseToVerifier throws and sends error on failure`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } throws OpenID4VPExceptions.InvalidData("VP token construction failed", "test")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, """{"received":true}""", mapOf())

        val thrown = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.sendVPResponseToVerifier(emptyList())
        }
        assertEquals("VP token construction failed", thrown.message)
    }

    // --- constructErrorInfo ---

    @Test
    fun `constructErrorInfo produces spec-compliant error structure`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAuthorizationErrorResponse(any(), any(), any())
        } returns mapOf(
            "error" to "invalid_request",
            "error_description" to "Missing nonce",
            "state" to "test-state"
        )

        val result = openID4VP.constructErrorInfo(OpenID4VPExceptions.MissingInput("nonce", "", "test"))

        assertTrue(result.containsKey("error"))
        assertTrue(result.containsKey("error_description"))
    }
}

