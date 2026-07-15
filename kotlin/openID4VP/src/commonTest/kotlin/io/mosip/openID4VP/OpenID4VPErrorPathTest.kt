package io.mosip.openID4VP

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR_DESCRIPTION
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OpenID4VPErrorPathTest {

    @BeforeTest
    fun mockBase64() {
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg<ByteArray>())
        }
    }

    @AfterTest
    fun unmock() {
        unmockkAll()
    }

    private fun openID4VP() = OpenID4VP(traceabilityId = "trace-1")

    @Test
    fun `constructVPResponse returns error info when no authorization request was validated`() {
        val response = openID4VP().constructVPResponse(emptyList())

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, response[ERROR])
        assertEquals(
            "The wallet encountered an internal error while preparing the authorization response.",
            response[ERROR_DESCRIPTION]
        )
    }

    @Test
    fun `constructUnsignedVPToken fails when no authorization request was validated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.VerifiablePresentationConstructionFailure> {
            openID4VP().constructUnsignedVPToken(emptyMap())
        }

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, exception.errorCode)
        assertEquals(
            "The wallet encountered an internal error while preparing the presentation.",
            exception.message
        )
    }

    @Test
    fun `sendVPResponseToVerifier fails when no authorization request was validated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.AuthorizationResponseConstructionFailure> {
            openID4VP().sendVPResponseToVerifier(emptyList())
        }

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, exception.errorCode)
    }

    @Test
    fun `sendErrorInfoToVerifier fails when the response uri is unknown`() {
        val exception = assertFailsWith<OpenID4VPExceptions.ErrorDispatchFailure> {
            openID4VP().sendErrorInfoToVerifier(RuntimeException("boom"))
        }

        assertEquals(OpenID4VPErrorCodes.ERROR_DISPATCH_FAILURE, exception.errorCode)
        assertTrue(exception.message.contains("Response URI is not set"))
    }

    @Test
    fun `constructErrorInfo renders an OpenID4VP exception`() {
        val response = openID4VP().constructErrorInfo(
            OpenID4VPExceptions.InvalidVerifier("unknown client", "test")
        )

        assertEquals(OpenID4VPErrorCodes.INVALID_CLIENT, response[ERROR])
        assertEquals("unknown client", response[ERROR_DESCRIPTION])
    }

    @Test
    fun `constructErrorInfo wraps a non-OpenID4VP exception as a server error`() {
        val response = openID4VP().constructErrorInfo(RuntimeException("boom"))

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, response[ERROR])
        assertEquals("boom", response[ERROR_DESCRIPTION])
    }

    @Test
    fun `constructErrorInfo falls back to a generic description for a message-less exception`() {
        val response = openID4VP().constructErrorInfo(RuntimeException())

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, response[ERROR])
        assertEquals("Unknown internal error", response[ERROR_DESCRIPTION])
    }

    @Test
    fun `authenticateVerifier rejects an authorization request with no client_id`() {
        val exception = assertFailsWith<OpenID4VPExceptions> {
            openID4VP().authenticateVerifier(mapOf("response_type" to "vp_token"))
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
    }

    @Test
    fun `authenticateVerifier rejects an url encoded request with no query parameters`() {
        assertFailsWith<OpenID4VPExceptions> {
            openID4VP().authenticateVerifier("openid4vp://authorize")
        }
    }
}
