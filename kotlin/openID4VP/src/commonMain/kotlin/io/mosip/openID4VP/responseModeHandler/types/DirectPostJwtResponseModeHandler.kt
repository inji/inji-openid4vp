package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler

private val className = DirectPostJwtResponseModeHandler::class.simpleName!!

class DirectPostJwtResponseModeHandler : ResponseModeBasedHandler() {

    override fun validate(
        clientMetadata: ClientMetadataDraft23?,
        walletMetadata: WalletMetadata?,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        requireNotNull(clientMetadata) {
            throwInvalidDataException("client_metadata must be present for given response mode")
        }

        val alg = clientMetadata.authorizationEncryptedResponseAlg
            ?: throwMissingInputException("authorization_encrypted_response_alg")

        val enc = clientMetadata.authorizationEncryptedResponseEnc
            ?: throwMissingInputException("authorization_encrypted_response_enc")

        val jwks = clientMetadata.jwks
            ?: throwMissingInputException("jwks")

        validateEncryption(
            verifierEncryptionAlg = listOf(alg),
            verifierEnc = listOf(enc),
            walletMetadata = walletMetadata,
            shouldValidate = shouldValidateWithWalletMetadata
        )

        if (jwks.keys.none { it.alg == alg && it.use == "enc" }) {
            throwInvalidDataException("No jwk matching the specified algorithm found for encryption")
        }
    }

    override fun validate(
        clientMetadata: ClientMetadata?,
        walletMetadata: WalletMetadata?,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        requireNotNull(clientMetadata) {
            throwInvalidDataException("client_metadata must be present for given response mode")
        }

        val encValues = clientMetadata.encryptedResponseEncValuesSupported
        if (encValues.isNullOrEmpty()) {
            throwMissingInputException("encrypted_response_enc_values_supported")
        }

        val jwks = clientMetadata.jwks
            ?: throwMissingInputException("jwks")

        val encryptionKeys = jwks.keys.filter { it.use == "enc" }
        if (encryptionKeys.isEmpty()) {
            throwInvalidDataException("No encryption jwk found in client_metadata.jwks")
        }

        val verifierEncryptionAlgs = encryptionKeys.mapNotNull { it.alg }
        validateEncryption(
            verifierEncryptionAlg = verifierEncryptionAlgs,
            verifierEnc = encValues,
            walletMetadata = walletMetadata,
            shouldValidate = shouldValidateWithWalletMetadata
        )
    }

    private fun validateEncryption(
        verifierEncryptionAlg: List<String>,
        verifierEnc: List<String>,
        walletMetadata: WalletMetadata?,
        shouldValidate: Boolean
    ) {
        if (shouldValidate) {
            requireNotNull(walletMetadata) {
                throwInvalidDataException("wallet_metadata must be present")
            }

            val supportedAlgs = walletMetadata.authorizationEncryptionAlgValuesSupported
                ?: throwInvalidDataException("authorization_encryption_alg_values_supported must be present in wallet_metadata")

            val supportedAlgValues = supportedAlgs.map { it.value }
            if (!verifierEncryptionAlg.any { supportedAlgValues.contains(it) }) {
                throwInvalidDataException("Authorization response encryption algorithm is not supported")
            }

            val supportedEncs = walletMetadata.authorizationEncryptionEncValuesSupported
                ?: throwInvalidDataException("authorization_encryption_enc_values_supported must be present in wallet_metadata")

            val supportedEncValues = supportedEncs.map { it.value }
            if (!verifierEnc.any { supportedEncValues.contains(it) }) {
                throwInvalidDataException("authorization_encrypted_response_enc is not supported")
            }
        }
    }

    private fun throwMissingInputException(fieldName: String): Nothing {
        throw OpenID4VPExceptions.MissingInput(listOf("client_metadata", fieldName), "", className)
    }

    private fun throwInvalidDataException(message: String): Nothing {
        throw OpenID4VPExceptions.InvalidData(message, className)
    }

    override fun sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletMetadata: WalletMetadata?
    ): NetworkResponse {
        val encryptedBodyParams = getAuthorizationResponse(
            authorizationRequest,
            authorizationResponse,
            walletNonce,
            walletMetadata
        )

        return sendHTTPRequest(
            url = url,
            method = HttpMethod.POST,
            bodyParams = encryptedBodyParams,
            headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
        )
    }

    override fun getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletMetadata: WalletMetadata?
    ): Map<String, String> {
        return encryptResponse(
            authorizationRequest, walletNonce,
            authorizationResponse.toJsonEncodedMap(),
            walletMetadata
        )
    }

    override fun getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ): Map<String, String> {
        return authorizationResponse.toJsonEncodedMap()
    }

    override fun getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletMetadata: WalletMetadata?
    ): Jwk? {
        return SpecVersionHandler.from(authorizationRequest)
            .getVerifierPublicKey(authorizationRequest, walletMetadata, className)
    }

    private fun encryptResponse(
        authorizationRequest: AuthorizationRequest,
        walletNonce: String,
        responseParams: Map<String, String>,
        walletMetadata: WalletMetadata?
    ): Map<String, String> {
        val specVersionHandler = SpecVersionHandler.from(authorizationRequest)
        val jweHandler = specVersionHandler.getJWEHandler(authorizationRequest, walletNonce, walletMetadata, className)
        val encryptedBody = jweHandler.generateEncryptedResponse(responseParams)
        return mapOf("response" to encryptedBody)
    }

    private sealed class SpecVersionHandler {
        object V1 : SpecVersionHandler()
        object Draft23 : SpecVersionHandler()

        companion object {
            fun from(authorizationRequest: AuthorizationRequest): SpecVersionHandler {
                return if (authorizationRequest is AuthorizationPresentationExchangeRequest) Draft23 else V1
            }
        }

        fun getVerifierPublicKey(
            authorizationRequest: AuthorizationRequest,
            walletMetadata: WalletMetadata?,
            className: String
        ): Jwk {
            return when (this) {
                is Draft23 -> {
                    val clientMetadata = (authorizationRequest as AuthorizationPresentationExchangeRequest).clientMetadata!!
                    getEncryptionKey(clientMetadata.jwks!!, listOf(clientMetadata.authorizationEncryptedResponseAlg!!))
                }
                is V1 -> {
                    val clientMetadata = (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata
                        ?: throw OpenID4VPExceptions.InvalidData("client_metadata must be present for given response mode", className)
                    val verifierJwks = clientMetadata.jwks
                        ?: throw OpenID4VPExceptions.MissingInput(listOf("client_metadata", "jwks"), "", className)
                    val supportedAlgs = walletMetadata?.authorizationEncryptionAlgValuesSupported?.map { it.value }
                        ?: listOf(KeyManagementAlgorithm.ECDH_ES.value)
                    getEncryptionKey(verifierJwks, supportedAlgs)
                }
            }
        }

        private fun getEncryptionKey(jwks: io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks, algValues: List<String>): Jwk {
            return jwks.keys.first { it.use == "enc" && algValues.contains(it.alg) }
        }

        fun getJWEHandler(
            authorizationRequest: AuthorizationRequest,
            walletNonce: String,
            walletMetadata: WalletMetadata?,
            className: String
        ): JWEHandler {
            return when (this) {
                is Draft23 -> {
                    val clientMetadata = (authorizationRequest as AuthorizationPresentationExchangeRequest).clientMetadata!!
                    val verifierPublicKey = getVerifierPublicKey(authorizationRequest, walletMetadata, className)
                    JWEHandler(
                        keyEncryptionAlg = clientMetadata.authorizationEncryptedResponseAlg!!,
                        contentEncryptionAlg = clientMetadata.authorizationEncryptedResponseEnc!!,
                        publicKey = verifierPublicKey,
                        walletNonce = walletNonce,
                        verifierNonce = authorizationRequest.nonce
                    )
                }
                is V1 -> {
                    val clientMetadata = (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata
                        ?: throw OpenID4VPExceptions.InvalidData("client_metadata must be present for given response mode", className)
                    val encValues = clientMetadata.encryptedResponseEncValuesSupported
                    if (encValues.isNullOrEmpty()) {
                        throw OpenID4VPExceptions.InvalidData("Unsupported content encryption algorithm", className)
                    }
                    val walletEncValues = walletMetadata?.authorizationEncryptionEncValuesSupported?.map { it.value }
                        ?: listOf(ContentEncryptionAlgorithm.A256GCM.value)
                    val contentEncryptionAlgorithm = walletEncValues.firstOrNull { encValues.contains(it) }
                        ?: throw OpenID4VPExceptions.InvalidData("Unsupported content encryption algorithm", className)
                    val verifierPublicKey = getVerifierPublicKey(authorizationRequest, walletMetadata, className)
                    val verifierPublicKeyAlg = verifierPublicKey.alg
                        ?: throw OpenID4VPExceptions.InvalidData("Algorithm must be specified for the encryption key in jwks", className)
                    JWEHandler(
                        keyEncryptionAlg = verifierPublicKeyAlg,
                        contentEncryptionAlg = contentEncryptionAlgorithm,
                        publicKey = verifierPublicKey,
                        walletNonce = walletNonce,
                        verifierNonce = authorizationRequest.nonce
                    )
                }
            }
        }
    }
}
