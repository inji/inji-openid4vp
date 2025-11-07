package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition

data class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String?,
    var presentationDefinition: PresentationDefinition,
    val responseUri: String?,
    val redirectUri: String?,
    val nonce: String,
    val walletNonce: String?,
    val state: String?,
    var clientMetadata: ClientMetadata? = null,
    val clientIdScheme: String? = null
)  {

    companion object {

        fun validateAndCreateAuthorizationRequest(
            authorizationRequest: Map<String, Any>,
            trustedVerifiers: List<Verifier>,
            walletMetadata: WalletMetadata?,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean,
            walletNonce: String
        ): AuthorizationRequest {

            return getAuthorizationRequest(
                authorizationRequest.toMutableMap(),
                trustedVerifiers,
                walletMetadata,
                shouldValidateClient,
                setResponseUri,
                walletNonce
            )
        }

        fun validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: String,
            trustedVerifiers: List<Verifier>,
            walletMetadata: WalletMetadata?,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean,
            walletNonce: String
        ): AuthorizationRequest {

            val queryParameter = extractQueryParameters(urlEncodedAuthorizationRequest)
            return getAuthorizationRequest(
                queryParameter.toMutableMap(),
                trustedVerifiers,
                walletMetadata,
                shouldValidateClient,
                setResponseUri,
                walletNonce
            )
        }

        private fun getAuthorizationRequest(
            params: MutableMap<String, Any>,
            trustedVerifiers: List<Verifier>,
            walletMetadata: WalletMetadata?,
            shouldValidateClient: Boolean,
            setResponseUri: (String) -> Unit,
            walletNonce: String
        ): AuthorizationRequest {
            val authorizationRequestHandler = getAuthorizationRequestHandler(
                params,
                trustedVerifiers,
                walletMetadata,
                setResponseUri,
                shouldValidateClient,
                walletNonce
            )
            processAndValidateAuthorizationRequestParameter(authorizationRequestHandler)
            return authorizationRequestHandler.createAuthorizationRequest()
        }


        private fun processAndValidateAuthorizationRequestParameter(authorizationRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler) {
            authorizationRequestHandler.validateClientId()
            authorizationRequestHandler.fetchAuthorizationRequest()
            authorizationRequestHandler.setResponseUrl()
            authorizationRequestHandler.validateAndParseRequestFields()
        }

    }
}