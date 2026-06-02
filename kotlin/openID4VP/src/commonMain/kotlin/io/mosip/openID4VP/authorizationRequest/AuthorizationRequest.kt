package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.DCQLQuery
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition

open class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String?,
    val responseUri: String?,
    val redirectUri: String?,
    val nonce: String,
    val walletNonce: String?,
    val state: String?,
) {

    companion object {

        fun validateAndCreateAuthorizationRequest(
            authorizationRequest: Map<String, Any>,
            walletConfig: WalletConfig,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean,
            walletNonce: String
        ): AuthorizationRequest {

            return getAuthorizationRequest(
                authorizationRequest.toMutableMap(),
                walletConfig,
                shouldValidateClient,
                setResponseUri,
                walletNonce
            )
        }

        fun validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: String,
            walletConfig: WalletConfig,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean,
            walletNonce: String
        ): AuthorizationRequest {

            val queryParameter = extractQueryParameters(urlEncodedAuthorizationRequest)
            return getAuthorizationRequest(
                queryParameter.toMutableMap(),
                walletConfig,
                shouldValidateClient,
                setResponseUri,
                walletNonce
            )
        }

        private fun getAuthorizationRequest(
            params: MutableMap<String, Any>,
            walletConfig: WalletConfig,
            shouldValidateClient: Boolean,
            setResponseUri: (String) -> Unit,
            walletNonce: String
        ): AuthorizationRequest {
            val authorizationRequestHandler = getAuthorizationRequestHandler(
                params,
                walletConfig,
                setResponseUri,
                shouldValidateClient,
                walletNonce
            )
            return authorizationRequestHandler.handle()
        }
    }
}

class AuthorizationPresentationExchangeRequest(
    clientId: String,
    responseType: String,
    responseMode: String?,
    responseUri: String?,
    redirectUri: String?,
    nonce: String,
    walletNonce: String?,
    state: String?,
    var presentationDefinition: PresentationDefinition,
    var clientMetadata: ClientMetadataDraft23? = null,
) : AuthorizationRequest(
    clientId = clientId,
    responseType = responseType,
    responseMode = responseMode,
    responseUri = responseUri,
    redirectUri = redirectUri,
    nonce = nonce,
    walletNonce = walletNonce,
    state = state,
)

class AuthorizationDcqlRequest(
    clientId: String,
    responseType: String,
    responseMode: String?,
    responseUri: String?,
    redirectUri: String?,
    nonce: String,
    walletNonce: String?,
    state: String?,
    var clientMetadata: ClientMetadata? = null,
    val dcqlQuery: DCQLQuery,
) : AuthorizationRequest(
    clientId = clientId,
    responseType = responseType,
    responseMode = responseMode,
    responseUri = responseUri,
    redirectUri = redirectUri,
    nonce = nonce,
    walletNonce = walletNonce,
    state = state,
)
