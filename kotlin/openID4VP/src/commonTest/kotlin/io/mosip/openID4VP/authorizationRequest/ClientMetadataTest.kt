package io.mosip.openID4VP.authorizationRequest

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.*
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.constants.ResponseMode.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import kotlinx.serialization.json.Json
import kotlin.test.*

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
