package io.mosip.openID4VP.authorizationRequest.clientMetadata

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.MsoMdocVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.testData.walletConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ClientMetadataUtilTest {

    @Test
    fun `of maps the spec version to its client metadata handler`() {
        assertEquals(
            ClientMetadataSpecVersionHandler.DRAFT_23,
            ClientMetadataSpecVersionHandler.of(SpecVersion.DRAFT_23)
        )
        assertEquals(
            ClientMetadataSpecVersionHandler.V1,
            ClientMetadataSpecVersionHandler.of(SpecVersion.V1)
        )
    }

    @Test
    fun `parseAndValidate deserializes V1 client metadata supplied as a json string`() {
        val parameters = mutableMapOf<String, Any>(
            CLIENT_METADATA.value to """
                {
                  "client_name": "Requester name",
                  "vp_formats_supported": { "mso_mdoc": { "alg": ["ES256"] } },
                  "encrypted_response_enc_values_supported": ["A256GCM"]
                }
            """.trimIndent()
        )

        ClientMetadataSpecVersionHandler.V1.parseAndValidate(parameters, false, walletConfig)

        val clientMetadata = parameters[CLIENT_METADATA.value] as ClientMetadata
        assertEquals("Requester name", clientMetadata.clientName)
        assertEquals(listOf("A256GCM"), clientMetadata.encryptedResponseEncValuesSupported)
        assertTrue(clientMetadata.vpFormatsSupported.containsKey("mso_mdoc"))
    }

    @Test
    fun `parseAndValidate keeps an already parsed draft 23 client metadata`() {
        val clientMetadata = ClientMetadataDraft23(
            clientName = "verifier",
            vpFormats = mapOf("ldp_vp" to mapOf("proof_type" to listOf("Ed25519Signature2018")))
        )
        val parameters = mutableMapOf<String, Any>(CLIENT_METADATA.value to clientMetadata)

        ClientMetadataSpecVersionHandler.DRAFT_23.parseAndValidate(parameters, false, walletConfig)

        assertSame(clientMetadata, parameters[CLIENT_METADATA.value])
    }

    @Test
    fun `parseAndValidate keeps an already parsed V1 client metadata`() {
        val clientMetadata = ClientMetadata(
            clientName = "verifier",
            vpFormatsSupported = mapOf("mso_mdoc" to MsoMdocVpFormatSupported())
        )
        val parameters = mutableMapOf<String, Any>(CLIENT_METADATA.value to clientMetadata)

        ClientMetadataSpecVersionHandler.V1.parseAndValidate(parameters, false, walletConfig)

        assertSame(clientMetadata, parameters[CLIENT_METADATA.value])
    }

    @Test
    fun `parseAndValidate rejects draft 23 client metadata that is neither a string nor a map`() {
        val parameters = mutableMapOf<String, Any>(CLIENT_METADATA.value to 42)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClientMetadataSpecVersionHandler.DRAFT_23.parseAndValidate(parameters, false, walletConfig)
        }
        assertOpenId4VPException(
            exception,
            "client_metadata must be of type String or Map",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `parseAndValidate rejects V1 client metadata that is neither a string nor a map`() {
        val parameters = mutableMapOf<String, Any>(CLIENT_METADATA.value to 42)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClientMetadataSpecVersionHandler.V1.parseAndValidate(parameters, false, walletConfig)
        }
        assertOpenId4VPException(
            exception,
            "client_metadata must be of type String or Map",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `validateAsPerResponseModeAndGetResponseEncryptionSpecification requires response_mode`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            ClientMetadataSpecVersionHandler.V1
                .validateAsPerResponseModeAndGetResponseEncryptionSpecification(
                    emptyMap(),
                    false,
                    walletConfig
                )
        }
        assertOpenId4VPException(
            exception,
            "Missing Input: response_mode param is required",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `validateAsPerResponseModeAndGetResponseEncryptionSpecification yields no spec for direct_post`() {
        assertNull(
            ClientMetadataSpecVersionHandler.DRAFT_23
                .validateAsPerResponseModeAndGetResponseEncryptionSpecification(
                    mapOf(RESPONSE_MODE.value to "direct_post"),
                    false,
                    walletConfig
                )
        )
        assertNull(
            ClientMetadataSpecVersionHandler.V1
                .validateAsPerResponseModeAndGetResponseEncryptionSpecification(
                    mapOf(RESPONSE_MODE.value to "direct_post"),
                    false,
                    walletConfig
                )
        )
    }
}
