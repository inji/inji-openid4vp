package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.MsoMdocVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.constants.EncryptionMethod
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DirectPostJwtValidationTest {

    private val handler = DirectPostJwtResponseModeHandler()

    @Test
    fun `draft23 requires authorization_encrypted_response_alg`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validate(draft23(alg = null), WalletConfig(), false)
        }
        assertEquals(
            "Missing Input: client_metadata->authorization_encrypted_response_alg param is required",
            exception.message
        )
    }

    @Test
    fun `draft23 requires authorization_encrypted_response_enc`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validate(draft23(enc = null), WalletConfig(), false)
        }
        assertEquals(
            "Missing Input: client_metadata->authorization_encrypted_response_enc param is required",
            exception.message
        )
    }

    @Test
    fun `draft23 requires jwks`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validate(draft23(jwks = null), WalletConfig(), false)
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `draft23 accepts metadata matching the wallet configuration`() {
        handler.validate(draft23(), WalletConfig(), true)
    }

    @Test
    fun `V1 requires encrypted_response_enc_values_supported`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validate(v1(encValues = null), WalletConfig(), false)
        }
        assertEquals(
            "Missing Input: client_metadata->encrypted_response_enc_values_supported param is required",
            exception.message
        )
    }

    @Test
    fun `V1 rejects an empty encrypted_response_enc_values_supported`() {
        assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validate(v1(encValues = emptyList()), WalletConfig(), false)
        }
    }

    @Test
    fun `V1 requires jwks`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validate(v1(jwks = null), WalletConfig(), false)
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `V1 requires at least one jwk carrying an algorithm`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validate(
                v1(jwks = Jwks(keys = listOf(Jwk(kty = "OKP", crv = "X25519", x = "x", alg = null)))),
                WalletConfig(),
                false
            )
        }
        assertEquals("No jwk with algorithm found in client_metadata.jwks", exception.message)
    }

    @Test
    fun `V1 falls back to the default encryption algorithm when the wallet declares none`() {
        handler.validate(v1(), WalletConfig(authorizationEncryptionAlgValuesSupported = null), false)
    }

    @Test
    fun `rejects metadata when the wallet declares no encryption algorithms`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validate(
                draft23(),
                WalletConfig(authorizationEncryptionAlgValuesSupported = null),
                true
            )
        }
        assertEquals(
            "authorization_encryption_alg_values_supported must be present in wallet_metadata",
            exception.message
        )
    }

    @Test
    fun `rejects an encryption algorithm the wallet does not support`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validate(
                draft23(alg = "RSA-OAEP"),
                WalletConfig(),
                true
            )
        }
        assertEquals("Authorization response encryption algorithm is not supported", exception.message)
    }

    @Test
    fun `rejects metadata when the wallet declares no encryption methods`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validate(
                draft23(),
                WalletConfig(authorizationEncryptionEncValuesSupported = null),
                true
            )
        }
        assertEquals(
            "authorization_encryption_enc_values_supported must be present in wallet_metadata",
            exception.message
        )
    }

    @Test
    fun `rejects a content encryption method the wallet does not support`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validate(draft23(enc = "A128CBC-HS256"), WalletConfig(), true)
        }
        assertEquals("authorization_encrypted_response_enc is not supported", exception.message)
    }

    @Test
    fun `selects the verifier encryption key for a dcql request`() {
        val key = handler.getVerifierPublicKeyForEncryption(dcqlRequest(v1()), WalletConfig())

        assertEquals("key-1", key?.kid)
    }

    @Test
    fun `falls back to the default algorithm when selecting a dcql verifier key`() {
        val key = handler.getVerifierPublicKeyForEncryption(
            dcqlRequest(v1()),
            WalletConfig(authorizationEncryptionAlgValuesSupported = null)
        )

        assertEquals("key-1", key?.kid)
    }

    @Test
    fun `requires client_metadata when selecting a dcql verifier key`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.getVerifierPublicKeyForEncryption(dcqlRequest(null), WalletConfig())
        }
        assertEquals("client_metadata must be present for given response mode", exception.message)
    }

    @Test
    fun `requires jwks when selecting a dcql verifier key`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.getVerifierPublicKeyForEncryption(dcqlRequest(v1(jwks = null)), WalletConfig())
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `rejects a dcql verifier jwks with no key matching the algorithm`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.getVerifierPublicKeyForEncryption(
                dcqlRequest(v1(jwks = Jwks(keys = listOf(jwk(alg = "RSA-OAEP"))))),
                WalletConfig()
            )
        }
        assertEquals("No jwk matching the specified algorithm found for encryption", exception.message)
    }

    @Test
    fun `breaks a tie between matching jwks using the enc key use`() {
        val jwks = Jwks(keys = listOf(jwk(kid = "sig-key", use = "sig"), jwk(kid = "enc-key", use = "enc")))

        val key = handler.getVerifierPublicKeyForEncryption(dcqlRequest(v1(jwks = jwks)), WalletConfig())

        assertEquals("enc-key", key?.kid)
    }

    @Test
    fun `rejects ambiguous matching jwks with no single enc key`() {
        val jwks = Jwks(keys = listOf(jwk(kid = "a", use = "enc"), jwk(kid = "b", use = "enc")))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.getVerifierPublicKeyForEncryption(dcqlRequest(v1(jwks = jwks)), WalletConfig())
        }
        assertEquals("Multiple jwks matching the specified algorithm found for encryption", exception.message)
    }

    private fun jwk(
        kid: String = "key-1",
        use: String? = "enc",
        alg: String? = EncryptionAlgorithm.ECDH_ES.value
    ) = Jwk(
        kty = "OKP",
        crv = "X25519",
        use = use,
        x = "BVFxIytOMlSBiJRIMdxU_UnJhqEUlpBJ4jcm8pMBGXo",
        alg = alg,
        kid = kid
    )

    private fun draft23(
        alg: String? = EncryptionAlgorithm.ECDH_ES.value,
        enc: String? = EncryptionMethod.A256GCM.value,
        jwks: Jwks? = Jwks(keys = listOf(jwk()))
    ) = ClientMetadataDraft23(
        vpFormats = mapOf("mso_mdoc" to emptyMap()),
        authorizationEncryptedResponseAlg = alg,
        authorizationEncryptedResponseEnc = enc,
        jwks = jwks
    )

    private fun v1(
        encValues: List<String>? = listOf(EncryptionMethod.A256GCM.value),
        jwks: Jwks? = Jwks(keys = listOf(jwk()))
    ) = ClientMetadata(
        vpFormatsSupported = mapOf(FormatType.MSO_MDOC.value to MsoMdocVpFormatSupported()),
        encryptedResponseEncValuesSupported = encValues,
        jwks = jwks
    )

    private fun dcqlRequest(clientMetadata: ClientMetadata?) = AuthorizationDcqlRequest(
        clientId = "verifier-1",
        responseType = "vp_token",
        responseMode = "direct_post.jwt",
        responseUri = "https://verifier.example/response",
        redirectUri = null,
        nonce = "verifier-nonce",
        walletNonce = null,
        state = null,
        clientMetadata = clientMetadata,
        dcqlQuery = DCQLQuery(
            credentials = listOf(CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value))
        )
    )
}
