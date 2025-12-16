package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
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
        walletMetadata: WalletMetadata?,
        shouldValidateWithWalletMetadata: Boolean
    ){
        return
    }

    abstract fun sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
    ): NetworkResponse

    fun setResponseUrl(
        authorizationRequestParameters: Map<String, Any>,
        setResponseUri: (String) -> Unit
    ) {
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
        validate(RESPONSE_URI.value, responseUri, className)
        if (!isValidUrl(responseUri!!)) {
            throw OpenID4VPExceptions.InvalidData("${RESPONSE_URI.value} data is not valid", className)
        }
        setResponseUri(responseUri)
    }

    abstract fun getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String
    ): Map<String, String>

    abstract fun getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ): Map<String, String>
}