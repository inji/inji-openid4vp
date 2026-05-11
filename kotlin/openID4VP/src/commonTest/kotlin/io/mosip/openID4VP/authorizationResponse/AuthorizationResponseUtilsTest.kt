package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.extractQueryParameters
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.constants.FormatType
import kotlin.test.Test
import kotlin.test.assertEquals

class AuthorizationResponseUtilsTest {

    @Test
    fun `should convert the unsignedVPTokens to JSON successfully`() {
        val unsignedVPToken = UnsignedVPToken(
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

    @Test
    fun `should convert the url encoded query to map`() {
        val data = "openid4vp://authorize?client_id=mock-client&request_uri=https%3A%2F%2Fmock-client.com%2Fverifier%2Fget-auth-request-obj%2Fdid%3Fdraft%3Ddraft-23&request_uri_method=post"

        val decodedQueryParams = extractQueryParameters(data)

        assertEquals("{client_id=mock-client, request_uri=https://mock-client.com/verifier/get-auth-request-obj/did?draft=draft-23, request_uri_method=post}", decodedQueryParams.toString())
    }
}
