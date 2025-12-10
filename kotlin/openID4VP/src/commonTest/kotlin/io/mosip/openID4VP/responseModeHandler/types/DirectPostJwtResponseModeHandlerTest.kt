package io.mosip.openID4VP.responseModeHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletMetadata
import org.junit.Test
import kotlin.test.*

class DirectPostJwtResponseModeHandlerTest {

    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)
        mockkConstructor(JWEHandler::class)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    /** validation of client metadata **/

    @Test
    fun `should validate the mandatory fields of clientMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
    }

    @Test
    fun `should throw error if jwks field is missing in clientMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `should throw error if authorization_encrypted_response_enc field is missing in clientMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(
            "Missing Input: client_metadata->authorization_encrypted_response_enc param is required",
            exception.message
        )
    }

    @Test
    fun `should throw error if authorization_encrypted_response_alg field is missing in clientMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(
            "Missing Input: client_metadata->authorization_encrypted_response_alg param is required",
            exception.message
        )
    }

    @Test
    fun `should throw error if no jwk matching the key encryption algorithm is found`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(
            "No jwk matching the specified algorithm found for encryption",
            exception.message
        )
    }

    @Test
    fun `should throw error if no jwk matching the use key is found`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"sign","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(
            "No jwk matching the specified algorithm found for encryption",
            exception.message
        )
    }

    @Test
    fun `should validate the fields of clientMetadata with walletMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
    }

    @Test
    fun `should throw error if the key exchange algorithm does not match supported list from the walletMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{},"ldp_vc":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }
        assertEquals("authorization_encrypted_response_alg is not supported", exception.message)
    }


    @Test
    fun `should throw error if the encryption algorithm does not match supported list from the walletMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{},"ldp_vc":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }
        assertEquals("authorization_encrypted_response_enc is not supported", exception.message)
    }

    /** sending of authorization response **/

    @Test
    fun `should send the authorization response with JWE in requestBody successfully`() {
        val responseUri = "https://mock-verifier.com/response"
        val vpShareSuccessResponse = "VP shared successfully"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(200, vpShareSuccessResponse, emptyMap())

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "eytyiewr.....jewjr"

        val actualResponse = DirectPostJwtResponseModeHandler().sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            "walletNonce"
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = mapOf("response" to "eytyiewr.....jewjr"),
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
        }
        assertEquals(vpShareSuccessResponse, actualResponse.body)
    }

    /** finalizeAuthorizationResponse tests **/

    @Test
    fun `finalizeAuthorizationResponse should encrypt AuthorizationResponse successfully`() {
        val walletNonce = "test-wallet-nonce"
        val expectedEncryptedResponse =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.encrypted_payload.signature"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        val result = DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce
        )

        assertEquals(mapOf("response" to expectedEncryptedResponse), result)

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(any())
        }
    }

    @Test
    fun `finalizeAuthorizationResponse should use correct JWE configuration for AuthorizationResponse`() {
        val walletNonce = "wallet-nonce-123"
        val expectedEncryptedResponse = "encrypted.jwt.token"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        val result = DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce
        )

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(any())
        }

        assertEquals(mapOf("response" to expectedEncryptedResponse), result)
    }

    @Test
    fun `finalizeAuthorizationResponse should encrypt AuthorizationErrorResponse successfully`() {
        val walletNonce = "error-wallet-nonce"
        val errorResponse = AuthorizationErrorResponse(
            error = "invalid_request",
            errorDescription = "Test error description",
            state = "test-state"
        )

        val result = DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            errorResponse,
            walletNonce
        )

        assertEquals(
            mapOf(
                "error" to "invalid_request",
                "error_description" to "Test error description",
                "state" to "test-state"
            ), result
        )
    }

    @Test
    fun `finalizeAuthorizationResponse should find correct encryption key from jwks`() {
        val walletNonce = "jwk-test-nonce"
        val expectedEncryptedResponse = "jwk.encrypted.response"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        val result = DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce
        )

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(any())
        }
        assertEquals(mapOf("response" to expectedEncryptedResponse), result)
    }

    @Test
    fun `finalizeAuthorizationResponse should pass response params to JWE encryption for AuthorizationResponse`() {
        val walletNonce = "params-test-nonce"
        val expectedEncryptedResponse = "params.encrypted.response"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce
        )

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(
                match { params ->
                    params.isNotEmpty() &&
                            params.containsKey("vp_token") &&
                            params.containsKey("presentation_submission")
                }
            )
        }
    }

    @Test
    fun `finalizeAuthorizationResponse should handle AuthorizationErrorResponse with null state`() {
        val walletNonce = "null-state-nonce"
        val errorResponse = AuthorizationErrorResponse(
            error = "invalid_grant",
            errorDescription = "Invalid grant provided",
            state = null
        )

        val result = DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            errorResponse,
            walletNonce
        )

        assertEquals(mapOf(
            "error" to "invalid_grant",
            "error_description" to "Invalid grant provided",
        ), result)
    }

    @Test
    fun `finalizeAuthorizationResponse should return map with response key`() {
        val walletNonce = "response-key-nonce"
        val encryptedContent = "response.key.test.encrypted"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns encryptedContent

        val result = DirectPostJwtResponseModeHandler().finalizeAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce
        )

        assertEquals(1, result.size)
        assertEquals(encryptedContent, result["response"])
        assertTrue(result.containsKey("response"))
    }
}