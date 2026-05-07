package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.net.URI
import java.net.URLDecoder

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    trustedVerifiers: List<Verifier>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    shouldValidateClient: Boolean,
    walletNonce: String
): ClientIdSchemeBasedAuthorizationRequestHandler {
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)
    validate(CLIENT_ID.value, clientId, className)
    val clientIdScheme = extractClientIdScheme(authorizationRequestParameters)
    return when (clientIdScheme) {
        PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            shouldValidateClient,
            setResponseUri,
            walletNonce
        )
        ClientIdScheme.REDIRECT_URI.value -> RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        ClientIdScheme.DID.value -> DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        else -> throw OpenID4VPExceptions.InvalidData("Given client_id_scheme is not supported", className)
    }
}

fun extractQueryParameters(query: String): Map<String, Any> {
    try {
        val uri = URI(query)
        val queryParams: Map<String, String> = uri.rawQuery?.split("&")?.associate {
            val (key, value) = it.split("=")
            key to URLDecoder.decode(value, "UTF-8")
        } ?: throw OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : No Query params in the URI", className)

        return queryParams
    } catch (exception: Exception) {
        throw OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : ${exception.message}", className)
    }
}

fun validateAuthorizationRequestObjectAndParameters(
    params: Map<String, Any>,
    requestObject: Map<String, Any>,
    className: String,
) {
    if (params[CLIENT_ID.value] != requestObject[CLIENT_ID.value]) {
        throw OpenID4VPExceptions.MismatchingClientIDInRequest(className)
    }

    if (params.containsKey(CLIENT_ID_SCHEME.value) && params[CLIENT_ID_SCHEME.value] != requestObject[CLIENT_ID_SCHEME.value]) {
        throw OpenID4VPExceptions.MismatchingClientIdSchemeInRequest(className)
    }
}

fun extractClientIdScheme(authorizationRequestParameters: Map<String, Any>): String {
    if(authorizationRequestParameters.containsKey(CLIENT_ID_SCHEME.value)) {
        return getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)!!
    }
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)

    return if (components.size > 1) {
        val extractedPrefix = components[0]
        if (ClientIdScheme.fromValue(extractedPrefix) != null) {
            extractedPrefix
        } else {
            PRE_REGISTERED.value
        }
    } else {
        PRE_REGISTERED.value
    }
}


fun extractClientIdentifier(authorizationRequestParameters: Map<String, Any>): String {
    if(authorizationRequestParameters.containsKey(CLIENT_ID_SCHEME.value)) {
        return  getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    }
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)
    return if (components.size > 1) {
        when (ClientIdScheme.fromValue(components[0])) {
            // DID client ID scheme will have the client id itself with did prefix, example - did:example:123#1. So there will not be additional prefix stating client_id_scheme
            ClientIdScheme.DID -> clientId
            ClientIdScheme.REDIRECT_URI,
            ClientIdScheme.PRE_REGISTERED -> components[1]
            null -> clientId
        }
    } else {
        // client_id_scheme is optional (Fallback client_id_scheme - pre-registered) i.e., a : character is not present in the Client Identifier
        clientId
    }
}

fun validateWalletNonce(requestUriResponse: Map<String, Any>, walletNonce: String) {
    if (requestUriResponse[WALLET_NONCE.value] != walletNonce) {
        throw OpenID4VPExceptions.InvalidData("wallet_nonce provided in the authorization request is not the same as shared by wallet", className)
    }
}

fun validateResponseTypeSupported(responseType: String) {
    ResponseType.entries.find { it.value == responseType } ?: throw OpenID4VPExceptions.InvalidData(
        "Response type $responseType is not supported",
        className
    )
}
