package io.mosip.openID4VP

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.verifier.VerifierResponse
import kotlin.test.*

/**
 * Tests for OpenID4VP.kt error dispatch behavior from PR #111:
 * - safeSendError on authenticateVerifier failure
 * - sendErrorInfoToVerifier error codes per spec
 * - constructErrorInfo / constructVPResponse error map fallback
 * - Content-Type for direct_post error
 */
class OpenID4VPErrorDispatchTest {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        mockkObject(AuthorizationRequest)
        openID4VP = OpenID4VP("error-dispatch-test")
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    // --- safeSendError on auth failure ---

    @Test
    fun `authenticateVerifier sends error to verifier on failure when responseUri is set`() {
        val instance = OpenID4VP("test")
        setField(instance, "responseUri", "https://mock-verifier.com/response-uri")

        mockkConstructor(AuthorizationResponseHandler::class)
        every {
            anyConstructed<AuthorizationResponseHandler>().sendAuthorizationError(any(), any(), any())
        } returns VerifierResponse(200, null, """{"status":"received"}""", mapOf())

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } throws OpenID4VPExceptions.InvalidData("bad request data", "test")

        val thrown = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            instance.authenticateVerifier("bad")
        }

        assertNotNull(thrown.verifierResponse)
        assertEquals(200, thrown.verifierResponse!!.statusCode)
    }

    @Test
    fun `authenticateVerifier does not crash if error dispatch itself fails`() {
        val instance = OpenID4VP("test")

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } throws OpenID4VPExceptions.InvalidData("bad", "test")

        val thrown = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            instance.authenticateVerifier("bad")
        }
        assertEquals("bad", thrown.message)
        assertNull(thrown.verifierResponse)
    }

    // --- sendErrorInfoToVerifier error codes ---

    @Test
    fun `InvalidVerifier produces invalid_client error code`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidVerifier("untrusted", "test"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { it["error"] == "invalid_client" }, any()) }
    }

    @Test
    fun `AccessDenied produces access_denied error code`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.AccessDenied("user rejected", "test"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { it["error"] == "access_denied" }, any()) }
    }

    @Test
    fun `InvalidData produces invalid_request error code`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidData("bad data", "test"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { it["error"] == "invalid_request" }, any()) }
    }

    @Test
    fun `InvalidTransactionData produces invalid_transaction_data error code`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidTransactionData("not supported", "test"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { it["error"] == "invalid_transaction_data" }, any()) }
    }

    @Test
    fun `generic Exception is wrapped with server_error code`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(IllegalStateException("unexpected"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { it["error"] == "server_error" }, any()) }
    }

    @Test
    fun `VP construction failure sends server_error with generic description to verifier`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val innerException = OpenID4VPExceptions.InvalidData("Remote context loading issue", "test")
        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } throws OpenID4VPExceptions.VerifiablePresentationConstructionFailure(innerException, "test")

        every {
            mockHandler.sendAuthorizationError(any(), any(), any())
        } returns VerifierResponse(200, null, """{"ok":true}""", mapOf())

        val thrown = assertFailsWith<OpenID4VPExceptions.VerifiablePresentationConstructionFailure> {
            openID4VP.constructUnsignedVPToken(emptyMap())
        }

        assertEquals("server_error", thrown.errorCode)
        assertEquals("The wallet encountered an internal error while preparing the presentation.", thrown.message)
        val cause = assertIs<OpenID4VPExceptions.InvalidData>(thrown.cause)
        assertEquals("Remote context loading issue", cause.message)

        assertNotNull(thrown.verifierResponse)
    }

    // --- State in error response ---

    @Test
    fun `sendErrorInfoToVerifier includes state when authorizationRequest has state`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidData("test", "test"))

        verify {
            NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.POST, match { it.containsKey("state") }, any())
        }
    }

    @Test
    fun `sendErrorInfoToVerifier omits state when authorizationRequest state is null`() {
        openID4VP.authorizationRequest = createAuthorizationRequestWithState(null)
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidData("no state", "test"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { !it.containsKey("state") }, any()) }
    }

    @Test
    fun `sendErrorInfoToVerifier omits state when authorizationRequest state is empty`() {
        openID4VP.authorizationRequest = createAuthorizationRequestWithState("")
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidData("empty state", "test"))

        verify { NetworkManagerClient.sendHTTPRequest(any(), any(), match { !it.containsKey("state") }, any()) }
    }

    // --- ErrorDispatchFailure ---

    @Test
    fun `sendErrorInfoToVerifier throws ErrorDispatchFailure when responseUri is null`() {
        setField(openID4VP, "responseUri", null)

        val exception = assertFailsWith<OpenID4VPExceptions.ErrorDispatchFailure> {
            openID4VP.sendErrorInfoToVerifier(Exception("some error"))
        }
        assertTrue(exception.message!!.contains("Response URI is not set"))
    }

    @Test
    fun `sendErrorInfoToVerifier throws ErrorDispatchFailure on network error`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } throws Exception("Network error")

        val thrown = assertFailsWith<OpenID4VPExceptions.ErrorDispatchFailure> {
            openID4VP.sendErrorInfoToVerifier(Exception("test"))
        }
        assertTrue(thrown.message!!.contains("Failed to send error to verifier"))
    }

    // --- Content-Type ---

    @Test
    fun `sendErrorInfoToVerifier uses application_x-www-form-urlencoded content type`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(200, "{}", mapOf())

        openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.AccessDenied("denied", "test"))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                any(), HttpMethod.POST, any(),
                match { it["Content-Type"] == "application/x-www-form-urlencoded" }
            )
        }
    }

    // --- sendErrorInfoToVerifier returns VerifierResponse ---

    @Test
    fun `sendErrorInfoToVerifier returns VerifierResponse on successful dispatch`() {
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)

        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns
                NetworkResponse(200, """{"message":"received"}""", mapOf("Content-Type" to listOf("application/json")))

        val result = openID4VP.sendErrorInfoToVerifier(OpenID4VPExceptions.InvalidData("error", "test"))

        assertEquals(200, result.statusCode)
        assertEquals("{\"message\":\"received\"}", result.additionalParams)
    }
}

