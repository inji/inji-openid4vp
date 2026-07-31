package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkResponse

private val className = ResponseModeBasedHandler::class.simpleName!!

abstract class ResponseModeBasedHandler {

    open fun validate(
        clientMetadata: ClientMetadata?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ): ResponseEncryptionSpecification? = null

    open fun validate(
        clientMetadata: ClientMetadataDraft23?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ): ResponseEncryptionSpecification? = null

    fun getResponseEndpoint(authorizationRequestParameters: Map<String, Any>): String {
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
        validate(RESPONSE_URI.value, responseUri, className)
        if (!isValidUrl(responseUri!!)) {
            throw OpenID4VPExceptions.InvalidData("${RESPONSE_URI.value} data is not valid", className)
        }
        return responseUri
    }

    open fun getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ): Jwk? = null

    abstract fun getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ): Map<String, String>

    abstract fun sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ): NetworkResponse

    abstract fun getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ): Map<String, String>

    abstract fun sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ): NetworkResponse
}
