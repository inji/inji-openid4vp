package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23Serializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ClientMetadataDraft23Test {

    private fun decode(json: String): ClientMetadataDraft23 =
        Json.decodeFromString(ClientMetadataDraft23Serializer, json)

    @Test
    fun `deserializes every supported field`() {
        val metadata = decode(
            """
            {
              "client_name": "Verifier Inc",
              "logo_uri": "https://verifier.example/logo.png",
              "vp_formats": { "ldp_vp": { "proof_type": ["Ed25519Signature2018"] } },
              "authorization_encrypted_response_alg": "ECDH-ES",
              "authorization_encrypted_response_enc": "A256GCM",
              "jwks": {
                "keys": [
                  {
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVFxIytOMlSBiJRIMdxU_UnJhqEUlpBJ4jcm8pMBGXo",
                    "alg": "ECDH-ES",
                    "kid": "key-1"
                  }
                ]
              }
            }
            """.trimIndent()
        )

        assertEquals("Verifier Inc", metadata.clientName)
        assertEquals("https://verifier.example/logo.png", metadata.logoUri)
        assertEquals("ECDH-ES", metadata.authorizationEncryptedResponseAlg)
        assertEquals("A256GCM", metadata.authorizationEncryptedResponseEnc)
        assertEquals("key-1", metadata.jwks!!.keys.single().kid)
        assertEquals(
            mapOf("ldp_vp" to mapOf("proof_type" to listOf("Ed25519Signature2018"))),
            metadata.vpFormats
        )
    }

    @Test
    fun `leaves the optional fields null when absent`() {
        val metadata = decode("""{ "vp_formats": { "ldp_vp": {} } }""")

        assertNull(metadata.clientName)
        assertNull(metadata.logoUri)
        assertNull(metadata.authorizationEncryptedResponseAlg)
        assertNull(metadata.authorizationEncryptedResponseEnc)
        assertNull(metadata.jwks)
    }

    @Test
    fun `requires vp_formats`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode("""{ "client_name": "Verifier Inc" }""")
        }
        assertEquals(
            "Invalid Input: client_metadata->vp_formats value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `validate rejects empty vp_formats`() {
        val metadata = ClientMetadataDraft23(vpFormats = emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> { metadata.validate() }
        assertEquals(
            "Invalid Input: client_metadata->vp_formats value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `validate accepts a populated vp_formats`() {
        ClientMetadataDraft23(vpFormats = mapOf("ldp_vp" to emptyMap())).validate()
    }

    @Test
    fun `serializes client metadata back to json`() {
        val metadata = decode(
            """
            {
              "client_name": "Verifier Inc",
              "vp_formats": { "ldp_vp": { "proof_type": ["Ed25519Signature2018"] } },
              "authorization_encrypted_response_alg": "ECDH-ES",
              "authorization_encrypted_response_enc": "A256GCM"
            }
            """.trimIndent()
        )

        val json = Json.encodeToString(ClientMetadataDraft23Serializer, metadata)

        assertTrue(json.contains("\"client_name\":\"Verifier Inc\""))
        assertTrue(json.contains("\"authorization_encrypted_response_alg\":\"ECDH-ES\""))
    }
}
