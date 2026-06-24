package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.constants.FormatType
import kotlin.test.Test
import kotlin.test.assertEquals

class AuthorizationResponseUtilsJvmTest {

    @Test
    fun `should convert the unsignedVPTokens to JSON successfully`() {
        val unsignedVPToken = UnsignedVPToken(
            id = "random-uuid",
            format = FormatType.LDP_VC,
            holderKeyReference = "holder",
            signatureAlgorithm = "Ed25519Signature2020",
            dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
        )
        val unsignedVPTokens = mapOf(FormatType.LDP_VC to unsignedVPToken)

        val json = unsignedVPTokens.toJsonString()
        val expectedDataToSign = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("dataToSign".toByteArray(Charsets.UTF_8))
        assertEquals(
            """{"ldp_vc":{"format":"ldp_vc","holderKeyReference":"holder","signatureAlgorithm":"Ed25519Signature2020","dataToSign":"$expectedDataToSign"}}""",
            json
        )
    }
}
