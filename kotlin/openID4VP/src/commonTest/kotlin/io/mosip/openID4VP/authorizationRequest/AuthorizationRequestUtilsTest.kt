package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import kotlin.test.Test
import kotlin.test.assertEquals

class AuthorizationRequestUtilsTest {

    // --- extractClientIdScheme tests ---

    @Test
    fun `extractClientIdScheme should return pre-registered when client_id_scheme is explicitly set`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "mock-client", CLIENT_ID_SCHEME.value to PRE_REGISTERED.value)
        assertEquals(PRE_REGISTERED.value, extractClientIdScheme(params))
    }

    @Test
    fun `extractClientIdScheme should return did when client_id starts with did prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "did:web:example.com:verifier")
        assertEquals(ClientIdScheme.DID.value, extractClientIdScheme(params))
    }

    @Test
    fun `extractClientIdScheme should return redirect_uri when client_id starts with redirect_uri prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "redirect_uri:https://verifier.com/callback")
        assertEquals(ClientIdScheme.REDIRECT_URI.value, extractClientIdScheme(params))
    }

    @Test
    fun `extractClientIdScheme should return pre-registered when client_id has unrecognized prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "https://verifier.com")
        assertEquals(PRE_REGISTERED.value, extractClientIdScheme(params))
    }

    @Test
    fun `extractClientIdScheme should return pre-registered when client_id has no colon`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "govt-verifier")
        assertEquals(PRE_REGISTERED.value, extractClientIdScheme(params))
    }

    @Test
    fun `extractClientIdScheme should return pre-registered for foo prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "foo:bar")
        assertEquals(PRE_REGISTERED.value, extractClientIdScheme(params))
    }

    // --- extractClientIdentifier tests ---

    @Test
    fun `extractClientIdentifier should return full client_id when client_id_scheme is explicitly present`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "mock-client", CLIENT_ID_SCHEME.value to PRE_REGISTERED.value)
        assertEquals("mock-client", extractClientIdentifier(params))
    }

    @Test
    fun `extractClientIdentifier should return full client_id for did scheme`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "did:web:example.com:verifier")
        assertEquals("did:web:example.com:verifier", extractClientIdentifier(params))
    }

    @Test
    fun `extractClientIdentifier should strip prefix for redirect_uri scheme`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "redirect_uri:https://verifier.com/callback")
        assertEquals("https://verifier.com/callback", extractClientIdentifier(params))
    }

    @Test
    fun `extractClientIdentifier should return full client_id for unrecognized prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "https://verifier.com")
        assertEquals("https://verifier.com", extractClientIdentifier(params))
    }

    @Test
    fun `extractClientIdentifier should return full client_id when no colon present`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "govt-verifier")
        assertEquals("govt-verifier", extractClientIdentifier(params))
    }

    @Test
    fun `extractClientIdentifier should return full client_id for pre-registered prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "pre-registered:foo")
        assertEquals("pre-registered:foo", extractClientIdentifier(params))
    }

    @Test
    fun `extractClientIdentifier should return full client_id for foo prefix`() {
        val params = mapOf<String, Any>(CLIENT_ID.value to "foo:bar")
        assertEquals("foo:bar", extractClientIdentifier(params))
    }
}
