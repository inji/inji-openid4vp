package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkResponse

class DirectPostResponseModeHandler : ResponseModeBasedHandler() {
    override fun validate(
        clientMetadata: ClientMetadata?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ): ResponseEncryptionSpecification? = null

    override fun validate(
        clientMetadata: ClientMetadataDraft23?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ): ResponseEncryptionSpecification? = null

    override fun getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ): Map<String, String> {
        return authorizationResponse.toJsonEncodedMap()
    }

    override fun getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ): Map<String, String> {
        return authorizationResponse.toJsonEncodedMap()
    }

    override fun sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ): NetworkResponse {
        return sendHTTPRequest(
            url = dispatchInfo.responseUrl,
            method = HttpMethod.POST,
            bodyParams = getAuthorizationResponse(dispatchInfo, authorizationResponse, authorizationRequest),
            headers = mapOf("Content-Type" to APPLICATION_FORM_URL_ENCODED.value)
        )
    }

    override fun sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ): NetworkResponse {
        return sendHTTPRequest(
            url = dispatchInfo.responseUrl,
            method = HttpMethod.POST,
            bodyParams = getAuthorizationErrorResponse(dispatchInfo, authorizationResponse, authorizationRequest),
            headers = mapOf("Content-Type" to APPLICATION_FORM_URL_ENCODED.value)
        )
    }
}
