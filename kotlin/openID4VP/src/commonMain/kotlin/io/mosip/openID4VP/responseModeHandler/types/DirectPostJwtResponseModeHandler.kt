package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
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
        clientMetadata: ClientMetadata?,
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

        if (shouldValidateWithWalletMetadata) {
            validateWithWalletMetadata(
                clientAlg = alg,
                clientEnc = enc,
                walletMetadata = walletMetadata
            )
        }

        if (jwks.keys.none { it.alg == alg && it.use == "enc" }) {
            throwInvalidDataException("No jwk matching the specified algorithm found for encryption")
        }
    }

    private fun validateWithWalletMetadata(
        clientAlg: String,
        clientEnc: String,
        walletMetadata: WalletMetadata?
    ) {
        requireNotNull(walletMetadata) {
            throwInvalidDataException("wallet_metadata must be present")
        }

        val supportedAlgs = walletMetadata.authorizationEncryptionAlgValuesSupported
            ?: throwInvalidDataException("authorization_encryption_alg_values_supported must be present in wallet_metadata")

        if (KeyManagementAlgorithm.fromValue(clientAlg) !in supportedAlgs) {
            throwInvalidDataException("authorization_encrypted_response_alg is not supported")
        }

        val supportedEncs = walletMetadata.authorizationEncryptionEncValuesSupported
            ?: throwInvalidDataException("authorization_encryption_enc_values_supported must be present in wallet_metadata")

        if (ContentEncryptionAlgorithm.fromValue(clientEnc) !in supportedEncs) {
            throwInvalidDataException("authorization_encrypted_response_enc is not supported")
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
        walletNonce: String
    ): NetworkResponse {
        val encryptedBodyParams = finalizeAuthorizationResponse(
            authorizationRequest,
            authorizationResponse,
            walletNonce
        )

        return sendHTTPRequest(
            url = url,
            method = HttpMethod.POST,
            bodyParams = encryptedBodyParams,
            headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
        )
    }

    override fun finalizeAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String
    ): Map<String, String> {
        return encryptResponse(
            authorizationRequest, walletNonce,
            authorizationResponse.toJsonEncodedMap()
        )
    }

    override fun finalizeAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ): Map<String, String> {
        return encryptResponse(
            authorizationRequest, walletNonce,
            authorizationResponse.toJsonEncodedMap()
        )
    }

    private fun encryptResponse(
        authorizationRequest: AuthorizationRequest,
        walletNonce: String,
        responseParams: Map<String, String>
    ): Map<String, String> {
        val clientMetadata = authorizationRequest.clientMetadata!!

        val jwk =
            clientMetadata.jwks?.keys?.find { it.alg == clientMetadata.authorizationEncryptedResponseAlg && it.use == "enc" }!!

        val jweHandler = JWEHandler(
            keyEncryptionAlg = clientMetadata.authorizationEncryptedResponseAlg!!,
            contentEncryptionAlg = clientMetadata.authorizationEncryptedResponseEnc!!,
            publicKey = jwk,
            walletNonce = walletNonce,
            verifierNonce = authorizationRequest.nonce
        )
        val encryptedBody = jweHandler.generateEncryptedResponse(responseParams)

        return mapOf("response" to encryptedBody)
    }
}