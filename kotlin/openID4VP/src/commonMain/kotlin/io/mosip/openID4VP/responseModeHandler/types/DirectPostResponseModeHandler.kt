package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkResponse

class DirectPostResponseModeHandler : ResponseModeBasedHandler() {
    override fun validate(
        clientMetadata: ClientMetadata?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        return
    }

    override fun validate(
        clientMetadata: ClientMetadataDraft23?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        return
    }

    override fun getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ): Map<String, String> {
        return authorizationResponse.toJsonEncodedMap()
    }

    override fun getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ): Map<String, String> {
        return authorizationResponse.toJsonEncodedMap()
    }

    override fun sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ): NetworkResponse {
        val response = sendHTTPRequest(
            url = url,
            method = HttpMethod.POST,
            bodyParams = getAuthorizationResponse(authorizationRequest, authorizationResponse, walletNonce, walletConfig),
            headers = mapOf("Content-Type" to APPLICATION_FORM_URL_ENCODED.value)
        )
        return response
    }
}
