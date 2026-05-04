package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import kotlin.test.*

/**
 * Tests for AuthorizationResponse.kt sealed class changes from PR #111:
 * - AuthorizationResponse.PresentationExchange (Draft 23 flow)
 * - AuthorizationResponse.Dcql (V1 flow)
 * - toJsonEncodedMap for both variants
 */
class AuthorizationResponseV1Test {

    private val ldpVPToken = LdpVPToken(
        context = listOf("https://www.w3.org/2018/credentials/v1"),
        type = listOf("VerifiablePresentation"),
        verifiableCredential = listOf("VC1"),
        id = "urn:uuid:test",
        holder = "did:example:holder",
        proof = Proof(
            type = "Ed25519Signature2020",
            created = "2024-01-01T00:00:00Z",
            challenge = "nonce123",
            domain = "https://verifier.example.com",
            proofValue = "signature...",
            proofPurpose = "authentication",
            verificationMethod = "did:example:holder#key-1"
        )
    )

    private val presentationSubmission = PresentationSubmission(
        id = "submission-1",
        definitionId = "def-1",
        descriptorMap = listOf(
            DescriptorMap(id = "input-1", format = "ldp_vp", path = "$")
        )
    )

    // === PresentationExchange variant ===

    @Test
    fun `PresentationExchange toJsonEncodedMap contains vp_token and presentation_submission`() {
        val response = AuthorizationResponse.PresentationExchange(
            presentationSubmission = presentationSubmission,
            vpToken = VPTokenType.VPTokenElement(ldpVPToken),
            state = "test-state"
        )

        val map = response.toJsonEncodedMap()

        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertEquals("test-state", map["state"])
        assertEquals(3, map.size)
    }

    @Test
    fun `PresentationExchange toJsonEncodedMap omits state when null`() {
        val response = AuthorizationResponse.PresentationExchange(
            presentationSubmission = presentationSubmission,
            vpToken = VPTokenType.VPTokenElement(ldpVPToken),
            state = null
        )

        val map = response.toJsonEncodedMap()

        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertFalse(map.containsKey("state"))
        assertEquals(2, map.size)
    }

    // === Dcql variant ===

    @Test
    fun `Dcql toJsonEncodedMap contains vp_token as JSON serialized map`() {
        val vpTokenMap = mapOf(
            "credential_query_1" to "eyJhbGciOiJFZERTQSJ9...",
            "credential_query_2" to "mdoc_base64_data"
        )

        val response = AuthorizationResponse.Dcql(
            vpToken = vpTokenMap,
            state = "dcql-state"
        )

        val map = response.toJsonEncodedMap()

        assertTrue(map.containsKey("vp_token"))
        assertEquals("dcql-state", map["state"])
        // vp_token should be JSON-serialized
        val vpTokenJson = map["vp_token"]!!
        assertTrue(vpTokenJson.contains("credential_query_1"))
        assertTrue(vpTokenJson.contains("credential_query_2"))
    }

    @Test
    fun `Dcql toJsonEncodedMap omits state when null`() {
        val response = AuthorizationResponse.Dcql(
            vpToken = mapOf("query1" to "token1"),
            state = null
        )

        val map = response.toJsonEncodedMap()

        assertTrue(map.containsKey("vp_token"))
        assertFalse(map.containsKey("state"))
        assertEquals(1, map.size)
    }

    @Test
    fun `Dcql toJsonEncodedMap does not contain presentation_submission`() {
        val response = AuthorizationResponse.Dcql(
            vpToken = mapOf("q1" to "t1"),
            state = "s"
        )

        val map = response.toJsonEncodedMap()

        assertFalse(map.containsKey("presentation_submission"),
            "DCQL response must NOT include presentation_submission per V1 spec")
    }

    @Test
    fun `Dcql vp_token serializes nested structures correctly`() {
        val vpTokenMap = mapOf(
            "credential_query_1" to mapOf(
                "format" to "dc+sd-jwt",
                "credential" to "eyJ..."
            ) as Any
        )

        val response = AuthorizationResponse.Dcql(
            vpToken = vpTokenMap,
            state = null
        )

        val map = response.toJsonEncodedMap()
        val vpTokenJson = map["vp_token"]!!
        assertTrue(vpTokenJson.contains("dc+sd-jwt"))
        assertTrue(vpTokenJson.contains("credential_query_1"))
    }

    @Test
    fun `Dcql with empty vpToken map serializes to empty JSON object`() {
        val response = AuthorizationResponse.Dcql(
            vpToken = emptyMap(),
            state = null
        )

        val map = response.toJsonEncodedMap()
        assertEquals("{}", map["vp_token"])
    }
}

