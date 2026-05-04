package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.SpecVersion
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
): ClientIdPrefixBasedAuthorizationRequestHandler {
    validate(CLIENT_ID.value, getStringValue(authorizationRequestParameters, CLIENT_ID.value), className)
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val clientIdPrefix = extractClientIdPrefix(authorizationRequestParameters)
    val specVersion = findSpecVersion(clientId, clientIdPrefix, authorizationRequestParameters, trustedVerifiers)

    return when (clientIdPrefix) {
        ClientIdPrefix.PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = clientId,
            specVersion = specVersion,
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = walletMetadata,
            shouldValidateClient = shouldValidateClient,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        ClientIdPrefix.REDIRECT_URI.value -> RedirectUriPrefixAuthorizationRequestHandler(
            clientId = clientId,
            specVersion = specVersion,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = walletMetadata,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        ClientIdScheme.DID.value, ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value ->
            DecentralizedIdentifierPrefixAuthorizationRequestHandler(
                clientId = clientId,
                specVersion = specVersion,
                authorizationRequestParameters = authorizationRequestParameters,
                walletMetadata = walletMetadata,
                setResponseUri = setResponseUri,
                walletNonce = walletNonce
            )
        else -> throw OpenID4VPExceptions.InvalidData("Given client_id_prefix is not supported", className)
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
}

fun extractClientIdPrefix(authorizationRequestParameters: Map<String, Any>): String {
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)

    if (components.size > 1) {
        val prefix = components[0]
        if (prefix == ClientIdScheme.DID.value) {
            return ClientIdScheme.DID.value
        }
        if (ClientIdPrefix.fromValue(prefix) != null) {
            return prefix
        }
    }

    // Backward compat for draft-21: fall back to client_id_scheme parameter
    val clientIdScheme = getStringValue(authorizationRequestParameters, "client_id_scheme")
    if (clientIdScheme != null) {
        val scheme = ClientIdScheme.fromValue(clientIdScheme)
        if (scheme != null) {
            return when (scheme) {
                ClientIdScheme.REDIRECT_URI -> ClientIdPrefix.REDIRECT_URI.value
                ClientIdScheme.PRE_REGISTERED -> ClientIdPrefix.PRE_REGISTERED.value
                ClientIdScheme.DID -> ClientIdScheme.DID.value
            }
        }
    }

    return if (components.size > 1) components[0] else ClientIdPrefix.PRE_REGISTERED.value
}

fun extractClientIdPartOnly(authorizationRequestParameters: Map<String, Any>): String {
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)
    if (components.size > 1) {
        val prefix = components[0]
        if (prefix == ClientIdScheme.DID.value) {
            return clientId
        }
        if (ClientIdPrefix.fromValue(prefix) != null) {
            return components[1]
        }
    }
    // No recognized prefix (e.g., draft-21 style or pre-registered) — return full client_id
    return clientId
}

fun findSpecVersion(
    clientId: String,
    clientIdPrefix: String,
    authorizationRequestParameters: Map<String, Any>,
    trustedVerifiers: List<Verifier>
): SpecVersion {
    if (clientIdPrefix == ClientIdPrefix.REDIRECT_URI.value) {
        return findSpecVersionUsingRequestParameters(authorizationRequestParameters)
    } else if (clientIdPrefix == ClientIdScheme.DID.value) {
        return SpecVersion.DRAFT_23
    } else if (clientIdPrefix == ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value) {
        return SpecVersion.V1
    } else if (clientIdPrefix == ClientIdPrefix.PRE_REGISTERED.value) {
        val trustedVerifier = trustedVerifiers.firstOrNull { it.clientId == clientId }
        if (trustedVerifier != null) {
            return trustedVerifier.specVersion
        }
        return SpecVersion.V1
    }
    return findSpecVersionUsingRequestParameters(authorizationRequestParameters)
}

fun findSpecVersionUsingRequestParameters(authorizationRequestParameters: Map<String, Any>): SpecVersion {
    return if (authorizationRequestParameters.containsKey(DCQL_QUERY.value)) {
        SpecVersion.V1
    } else if (authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION.value) ||
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION_URI.value)
    ) {
        SpecVersion.DRAFT_23
    } else {
        // Default to DRAFT_23 when no query type is specified; Draft-23 validation
        // will provide explicit errors about missing presentation_definition
        SpecVersion.DRAFT_23
    }
}

fun validateRequestObjectSigningAlgSupported(walletMetadata: WalletMetadata?) {
    if (walletMetadata != null && walletMetadata.requestObjectSigningAlgValuesSupported.isNullOrEmpty()) {
        throw OpenID4VPExceptions.InvalidData(
            "request_object_signing_alg_values_supported is not present in wallet metadata",
            className
        )
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
