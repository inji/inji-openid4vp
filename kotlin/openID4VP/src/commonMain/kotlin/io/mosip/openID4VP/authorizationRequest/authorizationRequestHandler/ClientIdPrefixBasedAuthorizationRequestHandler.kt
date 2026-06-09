package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.NONCE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REDIRECT_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_METHOD
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_TYPE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.STATE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.TRANSACTION_DATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.WALLET_NONCE
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSpecVersionHandler
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.dcql.query.parseAndValidateDcqlQuery
import io.mosip.openID4VP.authorizationRequest.findSpecVersionUsingRequestParameters
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.authorizationRequest.validateResponseTypeSupported
import io.mosip.openID4VP.authorizationRequest.validateWalletNonce
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWS
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.RequestUriMethod
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import java.security.PublicKey
import java.util.logging.Logger

private val className = ClientIdPrefixBasedAuthorizationRequestHandler::class.simpleName!!

abstract class ClientIdPrefixBasedAuthorizationRequestHandler(
    val clientId: String,
    var specVersion: SpecVersion,
    var authorizationRequestParameters: MutableMap<String, Any>,
    val walletConfig: WalletConfig,
    private val setResponseUri: (String) -> Unit,
    val walletNonce: String,
) {
    private var shouldValidateWithWalletMetadata = false
    private var specVersionHandler: SpecVersionHandler = SpecVersionHandler.from(specVersion)

    open fun validateClientId() {
        return
    }

    abstract fun isSignedRequestSupported(): Boolean

    abstract fun isUnsignedRequestSupported(): Boolean

    abstract fun clientIdPrefix(): String

    fun handle(): AuthorizationRequest {
        validateClientId()
        fetchAuthorizationRequest()
        setResponseUrl()
        validateAndParseRequestFields()
        return createAuthorizationRequest()
    }

    internal fun setSpecVersionHandler(specVersion: SpecVersion) {
        this.specVersion = specVersion
        this.specVersionHandler = SpecVersionHandler.from(specVersion)
    }

    fun fetchAuthorizationRequest() {
        val requestUri = getStringValue(authorizationRequestParameters, REQUEST_URI.value)
        val request = getStringValue(authorizationRequestParameters, REQUEST.value)

        if (request != null && requestUri != null) {
            throw OpenID4VPExceptions.InvalidData(
                "Both 'request' and 'request_uri' cannot be present in same authorization request",
                className
            )
        }

        if (request != null) {
            handleRequestObjectAsValue(request)
            specVersion = findSpecVersionUsingRequestParameters(authorizationRequestParameters)
            setSpecVersionHandler(specVersion)
        } else if (requestUri != null) {
            handleRequestObjectByReference(requestUri)
        } else {
            handleUrlEncodedRequest()
        }
    }

    private fun handleRequestObjectByReference(requestUri: String) {
        val requestUriResponse: NetworkResponse
        if (!isSignedRequestSupported()) {
            throw OpenID4VPExceptions.InvalidData(
                "Signed request (via request_uri) is not supported for given client_id_prefix - ${this.clientIdPrefix()}",
                className
            )
        }

        if (!isValidUrl(requestUri)) {
            throw OpenID4VPExceptions.InvalidData(
                "${REQUEST_URI.value} data is not valid",
                className
            )
        }

        val requestUriMethod =
            getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"

        var httpMethod = try {
            determineHttpMethod(requestUriMethod)
        } catch (e: IllegalArgumentException) {
            throw OpenID4VPExceptions.InvalidData(
                "Unsupported HTTP method: $requestUriMethod",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_URI_METHOD
            )
        }

        // GET fallback: if POST but wallet doesn't support it, fall back to GET
        if (httpMethod == HttpMethod.POST && !walletConfig.supportedRequestUriMethods.contains(
                RequestUriMethod.POST
            )
        ) {
            Logger.getLogger(className)
                .warning("Wallet does not support POST method for request_uri. Proceeding with GET method.")
            httpMethod = HttpMethod.GET
        }

        var body: Map<String, String>? = null
        var headers: Map<String, String> = mapOf("accept" to ContentType.APPLICATION_JWT.value)

        if (httpMethod == HttpMethod.POST) {
            body = mapOf("wallet_nonce" to walletNonce)
            headers = headers.plus(
                "content-type" to ContentType.APPLICATION_FORM_URL_ENCODED.value,
            )
            isClientIdPrefixSupported(walletConfig)
            try {
                val processedWalletMetadata = getWalletMetadata(walletConfig)
                body = body.plus(
                    mapOf(
                        "wallet_metadata" to encodeToJsonString(
                            processedWalletMetadata,
                            "wallet_metadata",
                            className
                        )
                    )
                )
                shouldValidateWithWalletMetadata = true
            } catch (e: Exception) {
                Logger.getLogger(className)
                    .warning("Failed to process wallet metadata for POST request_uri: ${e.message}. Continuing without metadata.")
            }
        }
        try {
            requestUriResponse = sendHTTPRequest(requestUri, httpMethod, body, headers)
            if (!requestUriResponse.isOk()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Error while fetching request_uri: HTTP status code ${requestUriResponse.statusCode} & body: ${requestUriResponse.body}",
                    className,
                )
            }
            this.authorizationRequestParameters =
                this.validateRequestUriResponse(requestUriResponse, httpMethod)
            specVersion = findSpecVersionUsingRequestParameters(authorizationRequestParameters)
            setSpecVersionHandler(specVersion)
        } catch (e: OpenID4VPExceptions) {
            throw e
        } catch (e: Exception) {
            throw OpenID4VPExceptions.GenericFailure(
                errorCode = OpenID4VPErrorCodes.INVALID_REQUEST,
                "Network error while fetching request_uri: ${e.message}",
                className,
            )
        }
    }

    private fun handleUrlEncodedRequest() {
        if (!isUnsignedRequestSupported()) {
            throw OpenID4VPExceptions.InvalidData(
                "unsigned request is not supported for given client_id_prefix - ${this.clientIdPrefix()}",
                className
            )
        }
    }

    private fun handleRequestObjectAsValue(request: String) {
        validate(REQUEST.value, request, className, "jwt")
        if (!isSignedRequestSupported()) {
            throw OpenID4VPExceptions.InvalidData(
                "Signed request (via request) is not supported for given client_id_prefix - ${this.clientIdPrefix()}",
                className
            )
        }

        validateJWTRequest(request)
        val authorizationRequestObject = try {
            JWSHandler.extractDataJsonFromJws(request, JWSHandler.JwsPart.PAYLOAD)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Failed to parse payload from Authorization Request Object: ${e.message}",
                className
            )
        }

        validateAuthorizationRequestObjectAndParameters(
            this.authorizationRequestParameters,
            authorizationRequestObject,
            className
        )

        this.authorizationRequestParameters = authorizationRequestObject
    }

    private fun validateRequestUriResponse(
        requestUriResponse: NetworkResponse,
        httpMethod: HttpMethod
    ): MutableMap<String, Any> {
        val responseBody: String = requestUriResponse.body
        val headers = requestUriResponse.headers

        if (responseBody.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "Missing body in request_uri response",
                className
            )
        }

        if (!isValidContentType(headers)) {
            throw OpenID4VPExceptions.InvalidData(
                "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                className
            )
        }

        if (!isJWS(responseBody)) {
            throw OpenID4VPExceptions.InvalidData(
                "Authorization Request Object must be a signed JWT",
                className
            )
        }

        validateJWTRequest(responseBody)

        val authorizationRequestObject = try {
            JWSHandler.extractDataJsonFromJws(responseBody, JWSHandler.JwsPart.PAYLOAD)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Failed to parse payload from Authorization Request Object: ${e.message}",
                className
            )
        }

        if (httpMethod == HttpMethod.POST) {
            try {
                validateWalletNonce(authorizationRequestObject, walletNonce)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.InvalidData(
                    "Wallet nonce validation failed: ${e.message}",
                    className
                )
            }
        }

        validateAuthorizationRequestObjectAndParameters(
            authorizationRequestParameters,
            authorizationRequestObject,
            className
        )

        return authorizationRequestObject
    }

    private fun validateJWTRequest(jws: String) {
        try {
            val header = try {
                JWSHandler.extractDataJsonFromJws(jws, JWSHandler.JwsPart.HEADER)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.VerificationFailure(
                    "JWS header extraction failed: ${e.message}",
                    className,
                )
            }

            val typ = header["typ"] as? String
            if (typ != "oauth-authz-req+jwt") {
                throw OpenID4VPExceptions.InvalidData(
                    "Invalid typ in JWS header. Expected 'oauth-authz-req+jwt', found '${typ ?: "nil"}'",
                    className,
                    OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
                )
            }

            val algString = header["alg"] as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "'alg' is not present in JWS header",
                    className,
                    OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
                )

            validateAuthorizationSignatureAlgorithm(algString)

            val algorithm = SignatureAlgorithm.valueOf(algString)

            val kid = header["kid"] as? String

            val publicKey = extractPublicKey(algorithm = algorithm, kid = kid)

            try {
                JWSHandler.verify(jws, publicKey)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.VerificationFailure(
                    "JWS signature verification failed: ${e.message}",
                    className
                )
            }
        } catch (e: OpenID4VPExceptions) {
            throw OpenID4VPExceptions.InvalidData(
                "Request URI response validation failed - ${e.message}",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "Request URI response validation failed ${e.message}",
                className
            )
        }
    }

    abstract fun extractPublicKey(algorithm: SignatureAlgorithm, kid: String?): PublicKey

    private fun isValidContentType(headers: Map<String, List<String>>): Boolean {
        val contentTypeValues: List<String> = headers.entries
            .firstOrNull { it.key.equals("content-type", ignoreCase = true) }
            ?.value ?: return false
        return contentTypeValues.any { value ->
            value.contains(ContentType.APPLICATION_JWT.value, ignoreCase = true)
        }
    }

    private fun validateAuthorizationSignatureAlgorithm(algorithm: String) {
        if (shouldValidateWithWalletMetadata) {
            if (!walletConfig.requestObjectSigningAlgValuesSupported!!.contains(
                    SignatureAlgorithm.fromValue(algorithm)
                )
            )
                throw OpenID4VPExceptions.InvalidData(
                    "request_object_signing_alg is not supported by wallet",
                    className
                )
        }
    }

    abstract fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any>

    fun setResponseUrl() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value)
            ?: throw OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value), "", className)
        ResponseModeBasedHandlerFactory.get(responseMode)
            .setResponseUrl(authorizationRequestParameters, setResponseUri)
    }

    open fun validateAndParseRequestFields() {
        if (authorizationRequestParameters.containsKey(TRANSACTION_DATA.value)) {
            throw OpenID4VPExceptions.InvalidTransactionData(
                "Invalid Request: transaction_data is not supported in the authorization request",
                className
            )
        }
        val responseType = getStringValue(authorizationRequestParameters, RESPONSE_TYPE.value)
        validate(RESPONSE_TYPE.value, responseType, className)
        validateResponseTypeSupported(responseType!!)
        val nonce = getStringValue(authorizationRequestParameters, NONCE.value)
        validate(NONCE.value, nonce, className)
        val state = getStringValue(authorizationRequestParameters, STATE.value)
        state?.let {
            validate(STATE.value, state, className)
        }

        specVersionHandler.parseAndValidateClientMetadata(
            authorizationRequestParameters,
            shouldValidateWithWalletMetadata,
            walletConfig
        )

        specVersionHandler.validatePresentationRequest(
            authorizationRequestParameters,
            walletConfig
        )
    }

    private fun isClientIdPrefixSupported(walletConfig: WalletConfig) {
        val clientIdPrefix = clientIdPrefix()
        val prefix = ClientIdPrefix.fromValue(clientIdPrefix)
            ?: if (clientIdPrefix == ClientIdScheme.DID.value) ClientIdPrefix.DECENTRALIZED_IDENTIFIER else null
        if (prefix != null && walletConfig.clientIdPrefixesSupported?.contains(prefix) != true) {
            throw OpenID4VPExceptions.InvalidData(
                "client_id_prefix is not supported by wallet",
                className
            )
        }
    }

    fun createAuthorizationRequest(): AuthorizationRequest {
        return specVersionHandler.getAuthorizationRequest(authorizationRequestParameters)
    }

    private sealed class SpecVersionHandler {
        object Draft23 : SpecVersionHandler()
        object SpecV1 : SpecVersionHandler()

        companion object {
            fun from(specVersion: SpecVersion): SpecVersionHandler {
                return if (specVersion == SpecVersion.V1) SpecV1 else Draft23
            }
        }

        fun parseAndValidateClientMetadata(
            authorizationRequestParameters: MutableMap<String, Any>,
            shouldValidateWithWalletMetadata: Boolean,
            walletConfig: WalletConfig
        ) {
            val handler = when (this) {
                is Draft23 -> ClientMetadataSpecVersionHandler.DRAFT_23
                is SpecV1 -> ClientMetadataSpecVersionHandler.V1
            }
            handler.parseAndValidate(
                authorizationRequestParameters,
                shouldValidateWithWalletMetadata,
                walletConfig
            )
        }

        fun validatePresentationRequest(
            authorizationRequestParameters: MutableMap<String, Any>,
            walletConfig: WalletConfig
        ) {
            when (this) {
                is SpecV1 -> {
                    parseAndValidateDcqlQuery(authorizationRequestParameters)
                    val dcqlQuery = authorizationRequestParameters[AuthorizationRequestFieldConstants.DCQL_QUERY.value] as DCQLQuery
                    if (dcqlQuery.credentials.any { !it.requireCryptographicHolderBinding }) {
                        validate(STATE.value, getStringValue(authorizationRequestParameters, STATE.value), className)
                    }
                }

                is Draft23 -> {
                    parseAndValidatePresentationDefinition(
                        authorizationRequestParameters,
                        walletConfig.isPresentationDefinitionUriSupported
                    )
                }
            }
        }

        fun getAuthorizationRequest(authorizationRequestParameters: MutableMap<String, Any>): AuthorizationRequest {
            return when (this) {
                is Draft23 -> AuthorizationPresentationExchangeRequest(
                    clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!,
                    responseType = getStringValue(
                        authorizationRequestParameters,
                        RESPONSE_TYPE.value
                    )!!,
                    responseMode = getStringValue(
                        authorizationRequestParameters,
                        RESPONSE_MODE.value
                    ),
                    responseUri = getStringValue(
                        authorizationRequestParameters,
                        RESPONSE_URI.value
                    ),
                    redirectUri = getStringValue(
                        authorizationRequestParameters,
                        REDIRECT_URI.value
                    ),
                    nonce = getStringValue(authorizationRequestParameters, NONCE.value)!!,
                    walletNonce = getStringValue(
                        authorizationRequestParameters,
                        WALLET_NONCE.value
                    ),
                    state = getStringValue(authorizationRequestParameters, STATE.value),
                    presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value] as PresentationDefinition,
                    clientMetadata = authorizationRequestParameters[CLIENT_METADATA.value] as? ClientMetadataDraft23,
                )

                is SpecV1 -> AuthorizationDcqlRequest(
                    clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!,
                    responseType = getStringValue(
                        authorizationRequestParameters,
                        RESPONSE_TYPE.value
                    )!!,
                    responseMode = getStringValue(
                        authorizationRequestParameters,
                        RESPONSE_MODE.value
                    ),
                    responseUri = getStringValue(
                        authorizationRequestParameters,
                        RESPONSE_URI.value
                    ),
                    redirectUri = getStringValue(
                        authorizationRequestParameters,
                        REDIRECT_URI.value
                    ),
                    nonce = getStringValue(authorizationRequestParameters, NONCE.value)!!,
                    walletNonce = getStringValue(
                        authorizationRequestParameters,
                        WALLET_NONCE.value
                    ),
                    state = getStringValue(authorizationRequestParameters, STATE.value),
                    clientMetadata = authorizationRequestParameters[CLIENT_METADATA.value] as? ClientMetadata,
                    dcqlQuery = authorizationRequestParameters[AuthorizationRequestFieldConstants.DCQL_QUERY.value] as DCQLQuery,
                )
            }
        }
    }
}
