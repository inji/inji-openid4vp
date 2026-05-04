package io.mosip.openID4VP.authorizationRequest

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.*
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.constants.ResponseMode.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletMetadata
import kotlinx.serialization.json.Json
import kotlin.test.*

class ClientMetadataTest {
    private lateinit var actualException: Exception



    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should parse client metadata successfully`() {
        val authorizationRequestParam = mutableMapOf<String, Any>(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        try {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        } catch (e: Exception) {
            fail("Expected no exception, but got: ${e::class.simpleName} - ${e.message}")
        }
    }

    @Test
    fun `should throw invalid input exception if vp_formats field is not available`() {
        val invalidClientMetadata = """{"authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM"}"""
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        val ex = assertFailsWith<InvalidInput> {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
        assertEquals("Invalid Input: client_metadata->vp_formats value cannot be empty or null", ex.message)
    }

    @Test
    fun `should throw invalid input exception if vp_formats field is empty map`() {
        val invalidClientMetadata = """{"authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{}}"""
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        val ex = assertFailsWith<InvalidInput> {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
        assertEquals("Invalid Input: client_metadata->vp_formats value cannot be empty or null", ex.message)
    }

    @Test
    fun `should throw invalid input exception if name field is empty`() {
        val invalidClientMetadata = """{"client_name":"","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"mso_mdoc":{"alg":["ES256","EdDSA"]},"ldp_vp":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020","RsaSignature2018"]}}}"""
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        val ex = assertFailsWith<InvalidInput> {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
        assertEquals("Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer", ex.message)
    }

    @Test
    fun `should throw invalid input if client_name is null`() {
        val invalidClientMetadata = """{"client_name":null,"authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"mso_mdoc":{"alg":["ES256","EdDSA"]},"ldp_vp":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020","RsaSignature2018"]}}}"""
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        val ex = assertFailsWith<InvalidInput> {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
        assertEquals("Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer", ex.message)
    }

    @Test
    fun `should throw error when logo_uri is empty`() {
        val invalidClientMetadata = """{"client_name":"verifier","logo_uri":"","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"mso_mdoc":{"alg":["ES256","EdDSA"]},"ldp_vp":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020","RsaSignature2018"]}}}"""
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val ex = assertFailsWith<InvalidInput> {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
        assertEquals("Invalid Input: client_metadata->logo_uri value cannot be an empty string, null, or an integer", ex.message)
    }

    @Test
    fun `should throw missing input if encryption alg is missing`() {
        val invalidClientMetadata = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"abc","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["EdDSA"]}}}"""
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val ex = assertFailsWith<MissingInput> {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
        assertEquals("Missing Input: client_metadata->authorization_encrypted_response_alg param is required", ex.message)
    }

    @Test
    fun `should accept client metadata if response mode is direct_post`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            RESPONSE_MODE.value to DIRECT_POST.value
        )

        try {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        } catch (e: Exception) {
            fail("Expected no exception, but got: ${e::class.simpleName} - ${e.message}")
        }
    }

    @Test
    fun `should serialize and deserialize clientMetadata correctly`() {
        val clientMetadata = ClientMetadata(
            clientName = "Requestername",
            logoUri = "<logo_uri>",
            vpFormatsSupported = mapOf(
                "mso_mdoc" to MsoMdocVcFormatSupported(deviceAuthAlgValues = listOf(-7)),
                "ldp_vp" to LdpVcFormatSupported(proofTypeValues = listOf(io.mosip.openID4VP.constants.ProofType.Ed25519Signature2020, io.mosip.openID4VP.constants.ProofType.JsonWebSignature2020))
            ),
            jwks = Jwks(
                listOf(
                    Jwk(
                        kty = "OKP",
                        use = "X25519",
                        crv = "enc",
                        x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                        alg = "ECDH-ES",
                        kid = "ed-key1"
                    )
                )
            )
        )

        val json = Json.encodeToString(ClientMetadataSerializer, clientMetadata)
        val decoded = Json.decodeFromString(ClientMetadataSerializer, json)

        assertEquals(clientMetadata.clientName, decoded.clientName)
        assertEquals(clientMetadata.logoUri, decoded.logoUri)
        assertEquals(clientMetadata.vpFormatsSupported, decoded.vpFormatsSupported)
        assertEquals(clientMetadata.jwks, decoded.jwks)

    }
}
