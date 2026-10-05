package io.mosip.openID4VP.authorizationRequest

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.*
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.constants.ResponseMode.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import kotlinx.serialization.json.Json
import kotlin.test.*
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.MsoMdocVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.SdJwtVpFormatSupported
import io.mosip.openID4VP.constants.ProofType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ClientMetadataTest {
    private lateinit var actualException: Exception



    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should serialize and deserialize clientMetadata correctly`() {
        val clientMetadata = ClientMetadata(
            clientName = "Requestername",
            logoUri = "<logo_uri>",
            vpFormatsSupported = mapOf(
                "mso_mdoc" to MsoMdocVpFormatSupported(deviceAuthAlgValues = listOf(-7)),
                "ldp_vp" to LdpVpFormatSupported(proofTypeValues = listOf(io.mosip.openID4VP.constants.ProofType.Ed25519Signature2020, io.mosip.openID4VP.constants.ProofType.JsonWebSignature2020))
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

    private fun decode(json: String): ClientMetadata =
        Json.decodeFromString(ClientMetadataSerializer, json)

    @Test
    fun `deserializes the optional descriptive fields`() {
        val metadata = decode(
            """
            {
              "client_name": "Verifier Inc",
              "logo_uri": "https://verifier.example/logo.png",
              "vp_formats_supported": { "ldp_vp": {} }
            }
            """.trimIndent()
        )

        assertEquals("Verifier Inc", metadata.clientName)
        assertEquals("https://verifier.example/logo.png", metadata.logoUri)
    }

    @Test
    fun `leaves optional fields null when absent`() {
        val metadata = decode("""{ "vp_formats_supported": { "ldp_vp": {} } }""")

        assertNull(metadata.clientName)
        assertNull(metadata.logoUri)
        assertNull(metadata.encryptedResponseEncValuesSupported)
        assertNull(metadata.jwks)
    }

    @Test
    fun `requires vp_formats_supported`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode("""{ "client_name": "Verifier Inc" }""")
        }
        assertEquals(
            "Invalid Input: client_metadata->vp_formats_supported value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `requires vp_formats_supported to be an object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode("""{ "vp_formats_supported": "not-an-object" }""")
        }
        assertEquals(
            "Invalid Input: client_metadata->vp_formats_supported value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `deserializes the ldp vp format with proof types and cryptosuites`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": {
                "ldp_vp": {
                  "proof_type_values": ["Ed25519Signature2020", "JsonWebSignature2020"],
                  "cryptosuite_values": ["eddsa-rdfc-2022"]
                }
              }
            }
            """.trimIndent()
        )

        val format = assertIs<LdpVpFormatSupported>(metadata.vpFormatsSupported.getValue("ldp_vp"))
        assertEquals(
            listOf(ProofType.Ed25519Signature2020, ProofType.JsonWebSignature2020),
            format.proofTypeValues
        )
        assertEquals(listOf("eddsa-rdfc-2022"), format.cryptoSuiteValues)
        assertEquals(listOf("Ed25519Signature2020", "JsonWebSignature2020"), format.toAlgValuesSupported())
    }

    @Test
    fun `drops unrecognised ldp proof type values`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": {
                "ldp_vc": { "proof_type_values": ["Ed25519Signature2020", "UnknownSuite2099"] }
              }
            }
            """.trimIndent()
        )

        val format = assertIs<LdpVpFormatSupported>(metadata.vpFormatsSupported.getValue("ldp_vc"))
        assertEquals(listOf(ProofType.Ed25519Signature2020), format.proofTypeValues)
        assertNull(format.cryptoSuiteValues)
    }

    @Test
    fun `deserializes the mso mdoc format with its algorithm labels`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": {
                "mso_mdoc": {
                  "issuerauth_alg_values": [-7],
                  "deviceauth_alg_values": [-7, -9, -35]
                }
              }
            }
            """.trimIndent()
        )

        val format = assertIs<MsoMdocVpFormatSupported>(metadata.vpFormatsSupported.getValue("mso_mdoc"))
        assertEquals(listOf(-7), format.issuerAuthAlgValues)
        assertEquals(listOf(-7, -9, -35), format.deviceAuthAlgValues)
        assertEquals(listOf("ES256", "ESP256"), format.toAlgValuesSupported())
    }

    @Test
    fun `deserializes the sd-jwt formats with their algorithm values`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": {
                "dc+sd-jwt": {
                  "sd-jwt_alg_values": ["ES256"],
                  "kb-jwt_alg_values": ["ES256", "EdDSA"]
                },
                "vc+sd-jwt": {}
              }
            }
            """.trimIndent()
        )

        val dcSdJwt = assertIs<SdJwtVpFormatSupported>(metadata.vpFormatsSupported.getValue("dc+sd-jwt"))
        assertEquals(listOf("ES256"), dcSdJwt.sdJwtAlgValues)
        assertEquals(listOf("ES256", "EdDSA"), dcSdJwt.toAlgValuesSupported())

        val vcSdJwt = assertIs<SdJwtVpFormatSupported>(metadata.vpFormatsSupported.getValue("vc+sd-jwt"))
        assertNull(vcSdJwt.sdJwtAlgValues)
        assertNull(vcSdJwt.toAlgValuesSupported())
    }

    @Test
    fun `skips vp format entries with an unknown format key`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": { "unknown_format": {}, "ldp_vp": {} }
            }
            """.trimIndent()
        )

        assertEquals(setOf("ldp_vp"), metadata.vpFormatsSupported.keys)
    }

    @Test
    fun `skips vp format entries whose value is not an object`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": { "mso_mdoc": "not-an-object", "ldp_vp": {} }
            }
            """.trimIndent()
        )

        assertEquals(setOf("ldp_vp"), metadata.vpFormatsSupported.keys)
    }

    @Test
    fun `deserializes encrypted_response_enc_values_supported and jwks`() {
        val metadata = decode(
            """
            {
              "vp_formats_supported": { "ldp_vp": {} },
              "encrypted_response_enc_values_supported": ["A256GCM"],
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

        assertEquals(listOf("A256GCM"), metadata.encryptedResponseEncValuesSupported)
        val key = metadata.jwks!!.keys.single()
        assertEquals("OKP", key.kty)
        assertEquals("enc", key.use)
        assertEquals("ECDH-ES", key.alg)
        assertEquals("key-1", key.kid)
    }

    @Test
    fun `validate rejects empty vp_formats_supported`() {
        val metadata = ClientMetadata(vpFormatsSupported = emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> { metadata.validate() }
        assertEquals(
            "Invalid Input: client_metadata->vp_formats_supported value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `validate accepts a populated vp_formats_supported`() {
        val metadata = ClientMetadata(
            vpFormatsSupported = mapOf("ldp_vp" to LdpVpFormatSupported())
        )

        metadata.validate()
    }

    @Test
    fun `serializes client metadata back to json`() {
        val metadata = decode(
            """
            {
              "client_name": "Verifier Inc",
              "logo_uri": "https://verifier.example/logo.png",
              "vp_formats_supported": {
                "ldp_vp": { "proof_type_values": ["Ed25519Signature2020"], "cryptosuite_values": ["eddsa-rdfc-2022"] },
                "mso_mdoc": { "issuerauth_alg_values": [-7], "deviceauth_alg_values": [-7] },
                "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] }
              },
              "encrypted_response_enc_values_supported": ["A256GCM"]
            }
            """.trimIndent()
        )

        val json = Json.encodeToString(ClientMetadataSerializer, metadata)

        assertTrue(json.contains("\"client_name\":\"Verifier Inc\""))
        assertTrue(json.contains("\"proof_type_values\":[\"Ed25519Signature2020\"]"))
        assertTrue(json.contains("\"issuerauth_alg_values\":[-7]"))
        assertTrue(json.contains("\"sd-jwt_alg_values\":[\"ES256\"]"))
        assertTrue(json.contains("\"encrypted_response_enc_values_supported\":[\"A256GCM\"]"))
    }
}
