package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.testData.presentationSubmission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class AuthorizationResponseTest {

    private val ldpVPToken = LdpVPToken(
        context = listOf("context"),
        type = listOf("type"),
        verifiableCredential = listOf("VC1"),
        id = "id",
        holder = "holder",
        proof = Proof(
            type = "type",
            created = "time",
            challenge = "challenge",
            domain = "domain",
            proofValue = "eryy....ewr",
            proofPurpose = "authentication",
            verificationMethod = "did:example:holder#key-1"
        )
    )

    private val vpToken = VPTokenType.VPTokenElement(
        ldpVPToken
    )

    private val authorizationResponse = AuthorizationResponse(
        presentationSubmission = presentationSubmission,
        vpToken = vpToken,
        state = "state"
    )

    @Test
    fun `toJsonEncodedMap should return correct map representation`() {
        val map = authorizationResponse.toJsonEncodedMap()
        assertEquals(3, map.size)
        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertTrue(map.containsKey("state"))
        assertEquals("state", map["state"])
    }

    @Test
    fun `toJsonEncodedMap should filter out null values`() {
        val responseWithNullState = AuthorizationResponse(
            presentationSubmission = presentationSubmission,
            vpToken = vpToken,
            state = null
        )
        val map = responseWithNullState.toJsonEncodedMap()
        assertEquals(2, map.size)
        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertFalse(map.containsKey("state"))
    }
}
