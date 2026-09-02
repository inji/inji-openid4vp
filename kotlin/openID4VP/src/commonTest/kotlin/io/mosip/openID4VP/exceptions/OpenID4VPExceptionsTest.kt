package io.mosip.openID4VP.exceptions

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR_DESCRIPTION
import io.mosip.openID4VP.verifier.VerifierResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class OpenID4VPExceptionsTest {

    private val className = "OpenID4VPExceptionsTest"

    @Test
    fun `exposes the error code message and defaults`() {
        val exception = OpenID4VPExceptions.AccessDenied("user declined", className)

        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED, exception.errorCode)
        assertEquals("user declined", exception.message)
        assertEquals(className, exception.className)
        assertTrue(exception.notifyVerifier)
        assertNull(exception.verifierResponse)
    }

    @Test
    fun `converts to a verifier error response map`() {
        val exception = OpenID4VPExceptions.InvalidVerifier("unknown client", className)

        assertEquals(
            mutableMapOf(ERROR to OpenID4VPErrorCodes.INVALID_CLIENT, ERROR_DESCRIPTION to "unknown client"),
            exception.toErrorResponse()
        )
    }

    @Test
    fun `converts to an authorization error response carrying state`() {
        val exception = OpenID4VPExceptions.AccessDenied("denied", className)

        val response = exception.toAuthorizationErrorResponse("state-123")

        assertEquals(OpenID4VPErrorCodes.ACCESS_DENIED, response.error)
        assertEquals("denied", response.errorDescription)
        assertEquals("state-123", response.state)
    }

    @Test
    fun `converts to an authorization error response without state`() {
        val response = OpenID4VPExceptions.AccessDenied("denied", className)
            .toAuthorizationErrorResponse(null)

        assertNull(response.state)
    }

    @Test
    fun `retains the verifier response once recorded`() {
        val exception = OpenID4VPExceptions.AccessDenied("denied", className)
        val verifierResponse = VerifierResponse(200, headers = emptyMap())

        exception.setVerifierResponse(verifierResponse)

        assertSame(verifierResponse, exception.verifierResponse)
    }

    @Test
    fun `error companion logs without throwing`() {
        OpenID4VPExceptions.error("something went wrong", className)
    }

    @Test
    fun `InvalidVerifier reports invalid_client`() {
        val exception = OpenID4VPExceptions.InvalidVerifier("bad verifier", className)

        assertEquals(OpenID4VPErrorCodes.INVALID_CLIENT, exception.errorCode)
        assertEquals("bad verifier", exception.message)
    }

    @Test
    fun `InvalidTransactionData reports invalid_transaction_data`() {
        val exception = OpenID4VPExceptions.InvalidTransactionData("bad txn", className)

        assertEquals(OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA, exception.errorCode)
    }

    @Test
    fun `InvalidInputPattern joins a field path`() {
        val exception = OpenID4VPExceptions.InvalidInputPattern(listOf("a", "b"), className)

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals(
            "Invalid Input Pattern: a->b pattern is not matching with OpenId4VP specification",
            exception.message
        )
    }

    @Test
    fun `InvalidInputPattern renders a scalar field path as-is`() {
        val exception = OpenID4VPExceptions.InvalidInputPattern("client_id", className)

        assertEquals(
            "Invalid Input Pattern: client_id pattern is not matching with OpenId4VP specification",
            exception.message
        )
    }

    @Test
    fun `InvalidInputPattern renders an empty list path as-is`() {
        val exception = OpenID4VPExceptions.InvalidInputPattern(emptyList<String>(), className)

        assertEquals(
            "Invalid Input Pattern: [] pattern is not matching with OpenId4VP specification",
            exception.message
        )
    }

    @Test
    fun `JsonEncodingFailed describes the failing field`() {
        val exception = OpenID4VPExceptions.JsonEncodingFailed("vp_token", "boom", className)

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Json encoding failed for vp_token due to this error: boom", exception.message)
    }

    @Test
    fun `DeserializationFailure describes the failing field`() {
        val exception = OpenID4VPExceptions.DeserializationFailure("dcql_query", "boom", className)

        assertEquals("Deserializing for dcql_query failed due to this error: boom", exception.message)
    }

    @Test
    fun `InvalidLimitDisclosure reports the expected message`() {
        val exception = OpenID4VPExceptions.InvalidLimitDisclosure(className)

        assertEquals(
            "Invalid Input: constraints->limit_disclosure value should be preferred",
            exception.message
        )
    }

    @Test
    fun `InvalidQueryParams passes the message through`() {
        val exception = OpenID4VPExceptions.InvalidQueryParams("bad query", className)

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("bad query", exception.message)
    }

    @Test
    fun `InvalidData defaults to invalid_request and honours an override code`() {
        assertEquals(
            OpenID4VPErrorCodes.INVALID_REQUEST,
            OpenID4VPExceptions.InvalidData("bad", className).errorCode
        )
        assertEquals(
            OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT,
            OpenID4VPExceptions.InvalidData("bad", className, OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT).errorCode
        )
    }

    @Test
    fun `MissingInput renders string list and fallback field paths`() {
        assertEquals(
            "Missing Input: client_id param is required",
            OpenID4VPExceptions.MissingInput("client_id", "", className).message
        )
        assertEquals(
            "Missing Input: a->b param is required",
            OpenID4VPExceptions.MissingInput(listOf("a", "b"), "", className).message
        )
        assertEquals(
            "fallback message",
            OpenID4VPExceptions.MissingInput("", "fallback message", className).message
        )
        assertEquals(
            "fallback message",
            OpenID4VPExceptions.MissingInput(emptyList<String>(), "fallback message", className).message
        )
    }

    @Test
    fun `MissingInput can opt out of notifying the verifier`() {
        val exception = OpenID4VPExceptions.MissingInput("client_id", "", className, notifyVerifier = false)

        assertEquals(false, exception.notifyVerifier)
    }

    @Test
    fun `InvalidInput renders a message per field type`() {
        assertEquals(
            "Invalid Input: a->b value cannot be an empty string, null, or an integer",
            OpenID4VPExceptions.InvalidInput(listOf("a", "b"), "String", className).message
        )
        assertEquals(
            "Invalid Input: flag value must be either true or false",
            OpenID4VPExceptions.InvalidInput("flag", "Boolean", className).message
        )
        assertEquals(
            "Invalid Input: field value cannot be empty or null",
            OpenID4VPExceptions.InvalidInput("field", null, className).message
        )
    }

    @Test
    fun `InvalidInput can opt out of notifying the verifier`() {
        val exception = OpenID4VPExceptions.InvalidInput("field", "String", className, notifyVerifier = false)

        assertEquals(false, exception.notifyVerifier)
    }

    @Test
    fun `jws exceptions report invalid_request`() {
        val exceptions = listOf(
            OpenID4VPExceptions.PublicKeyExtractionFailed("no key", className),
            OpenID4VPExceptions.KidExtractionFailed("no kid", className),
            OpenID4VPExceptions.PublicKeyResolutionFailed("unresolved", className),
            OpenID4VPExceptions.InvalidSignature("bad signature", className),
            OpenID4VPExceptions.VerificationFailure("failed", className)
        )

        exceptions.forEach { assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, it.errorCode) }
        assertEquals("no key", exceptions[0].message)
        assertEquals("failed", exceptions[4].message)
    }

    @Test
    fun `UnsupportedPublicKeyType names the supported type`() {
        val exception = OpenID4VPExceptions.UnsupportedPublicKeyType(className)

        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }

    @Test
    fun `UnsupportedKeyExchangeAlgorithm reports the expected message`() {
        val exception = OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm(className)

        assertEquals("Required Key exchange algorithm is not supported", exception.message)
    }

    @Test
    fun `UnsupportedOperationException passes the message through`() {
        val exception = OpenID4VPExceptions.UnsupportedOperationException("nope", className)

        assertEquals("nope", exception.message)
    }

    @Test
    fun `JweEncryptionFailure retains its cause`() {
        val cause = IllegalStateException("root cause")
        val exception = OpenID4VPExceptions.JweEncryptionFailure("encrypt failed", className, cause)

        assertEquals("encrypt failed", exception.message)
        assertSame(cause, exception.cause)
    }

    @Test
    fun `ErrorDispatchFailure prefixes the message`() {
        val exception = OpenID4VPExceptions.ErrorDispatchFailure("timeout", className)

        assertEquals(OpenID4VPErrorCodes.ERROR_DISPATCH_FAILURE, exception.errorCode)
        assertEquals("Failed to send error to verifier: timeout", exception.message)
    }

    @Test
    fun `GenericFailure defaults to server_error and accepts an explicit code`() {
        assertEquals(
            OpenID4VPErrorCodes.SERVER_ERROR,
            OpenID4VPExceptions.GenericFailure("boom", className).errorCode
        )
        assertEquals(
            OpenID4VPErrorCodes.INVALID_SCOPE,
            OpenID4VPExceptions.GenericFailure(OpenID4VPErrorCodes.INVALID_SCOPE, "boom", className).errorCode
        )
    }

    @Test
    fun `client id mismatch exceptions report their fixed messages`() {
        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            OpenID4VPExceptions.MismatchingClientIDInRequest(className).message
        )
        assertEquals(
            "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            OpenID4VPExceptions.MismatchingClientIdSchemeInRequest(className).message
        )
    }

    @Test
    fun `construction failures report server_error and retain their cause`() {
        val cause = IllegalStateException("root cause")

        val vpFailure = OpenID4VPExceptions.VerifiablePresentationConstructionFailure(cause, className)
        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, vpFailure.errorCode)
        assertEquals(
            "The wallet encountered an internal error while preparing the presentation.",
            vpFailure.message
        )
        assertSame(cause, vpFailure.cause)

        val responseFailure = OpenID4VPExceptions.AuthorizationResponseConstructionFailure(cause, className)
        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, responseFailure.errorCode)
        assertEquals(
            "The wallet encountered an internal error while preparing the authorization response.",
            responseFailure.message
        )
        assertSame(cause, responseFailure.cause)
    }

    @Test
    fun `EncodingFailed prefixes the message and defaults to invalid_request`() {
        val exception = OpenID4VPExceptions.EncodingFailed(message = "boom", className = className)

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Encoding failed due to this error: boom", exception.message)
        assertEquals(
            OpenID4VPErrorCodes.SERVER_ERROR,
            OpenID4VPExceptions.EncodingFailed(OpenID4VPErrorCodes.SERVER_ERROR, "boom", className).errorCode
        )
    }
}
