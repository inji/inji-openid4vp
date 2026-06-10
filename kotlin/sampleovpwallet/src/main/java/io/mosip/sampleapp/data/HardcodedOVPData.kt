package io.mosip.sampleapp.data

import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.MsoMdocVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.constants.*

object HardcodedOVPData {
    fun getWalletConfig(): WalletConfig {
        return WalletConfig(
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to LdpVpFormatSupported(
                    proofTypeValues = listOf(ProofType.Ed25519Signature2020, ProofType.JsonWebSignature2020)
                ),
                VPFormatType.MSO_MDOC to MsoMdocVpFormatSupported(
                    deviceAuthAlgValues = listOf(-7)
                )
            ),
            clientIdPrefixesSupported = listOf(
                ClientIdPrefix.REDIRECT_URI,
                ClientIdPrefix.DECENTRALIZED_IDENTIFIER,
                ClientIdPrefix.PRE_REGISTERED
            ),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(EncryptionAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(EncryptionMethod.A256GCM)
        )
    }

    fun getListOfVerifiers(): List<Verifier> {
        // WARNING: Update these URLs to point to your verifier instance.
        val hardcodedVerifierJson = """
        [
            {
              "client_id": "mock-client",
              "response_uris": [
                "https://localhost:3000/verifier/vp-response"
              ],
              "jwks_uri": "https://localhost:3000/.well-known/jwks.json"
            }
        ]
    """.trimIndent()

        val objectMapper = jacksonObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        return objectMapper.readValue(hardcodedVerifierJson)
    }
}