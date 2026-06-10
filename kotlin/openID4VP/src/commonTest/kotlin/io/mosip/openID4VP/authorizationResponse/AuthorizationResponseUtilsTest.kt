package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.extractQueryParameters
import kotlin.test.Test
import kotlin.test.assertEquals

class AuthorizationResponseUtilsTest {

    @Test
    fun `should convert the url encoded query to map`() {
        val data = "openid4vp://authorize?client_id=mock-client&request_uri=https%3A%2F%2Fmock-client.com%2Fverifier%2Fget-auth-request-obj%2Fdid%3Fdraft%3Ddraft-23&request_uri_method=post"

        val decodedQueryParams = extractQueryParameters(data)

        assertEquals("{client_id=mock-client, request_uri=https://mock-client.com/verifier/get-auth-request-obj/did?draft=draft-23, request_uri_method=post}", decodedQueryParams.toString())
    }
}
