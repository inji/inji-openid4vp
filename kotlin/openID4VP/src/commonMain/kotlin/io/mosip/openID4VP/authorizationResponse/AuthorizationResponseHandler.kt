package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.OpenID4VPErrorFields
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.constructSigningResults
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ResponseMode
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.verifier.VerifierResponse
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

private val className = AuthorizationResponseHandler::class.java.simpleName

internal class AuthorizationResponseHandler(
    private val walletMetadata: WalletMetadata? = null
) {
    private lateinit var unsignedVPTokenResults: Map<FormatType, Pair<Any?, List<UnsignedVPToken>>>
    private lateinit var walletNonce: String
    private lateinit var signatureSuite: String
    private lateinit var formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>

    internal fun constructUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
        holderId: String?,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        signatureSuite: String?,
        nonce: String
    ): List<UnsignedVPToken> {

        val containsLdpVc = credentialsMap.any { (_, formatMap) ->
            formatMap.containsKey(FormatType.LDP_VC)
        }

        if (containsLdpVc) {
            require(!holderId.isNullOrEmpty()) {
                OpenID4VPExceptions.InvalidData(
                    "Holder ID cannot be null or empty for LDP VC format",
                    className
                )
            }
            require(!signatureSuite.isNullOrEmpty()) {
                OpenID4VPExceptions.InvalidData(
                    "Signature Suite cannot be null or empty for LDP VC format",
                    className
                )
            }
        }
        this.signatureSuite = signatureSuite ?: SignatureSuiteAlgorithm.Ed25519Signature2020.value

        createUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUri,
            signatureSuite = signatureSuite,
            nonce = nonce
        )

        return unsignedVPTokenResults.keys
            .sortedBy { it.value }
            .flatMap { format ->
                unsignedVPTokenResults[format]!!.second
            }
    }

    internal fun constructVPResponse(
        vpTokenSigningResults: List<VPTokenSigningResult>,
        authorizationRequest: AuthorizationRequest,
    ): Map<String, String> {

        val reconstructedResults = reconstructSigningResults(vpTokenSigningResults)

        return constructAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = reconstructedResults
        )
    }



    private fun createUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
        holderId: String?,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        signatureSuite: String?,
        nonce: String
    ): Map<FormatType, Pair<Any?, List<UnsignedVPToken>>> {
        walletNonce = nonce
        if (credentialsMap.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
                className
            )
        }
        this.unsignedVPTokenResults =
            createUnsignedVPTokens(
                authorizationRequest,
                responseUri,
                holderId,
                signatureSuite,
                credentialsMap
            )

        return unsignedVPTokenResults
    }

    internal fun constructAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        exception: Exception,
        walletNonce: String
    ): Map<String, Any> {
        this.walletNonce = walletNonce
        val authorizationResponse = when (exception) {
            is OpenID4VPExceptions -> exception.toAuthorizationErrorResponse(authorizationRequest?.state)
            else -> OpenID4VPExceptions.GenericFailure(
                message = exception.message ?: "Unknown internal error",
                className = OpenID4VP::class.simpleName.orEmpty()
            ).toAuthorizationErrorResponse(state = authorizationRequest?.state)
        }

        return ResponseModeBasedHandlerFactory.get(
            authorizationRequest?.responseMode ?: ResponseMode.DIRECT_POST.value
        ).getAuthorizationErrorResponse(
            authorizationRequest,
            authorizationResponse,
            this.walletNonce
        )
    }

    internal fun sendAuthorizationError(
        responseUri: String?,
        authorizationRequest: AuthorizationRequest?,
        exception: Exception
    ): VerifierResponse {
        if (responseUri == null) {
            throw OpenID4VPExceptions.ErrorDispatchFailure(
                message = "Response URI is not set. Cannot send error to verifier.",
                className = className
            )
        }
        try {
            val errorPayload = when (exception) {
                is OpenID4VPExceptions -> exception.toErrorResponse()
                else -> OpenID4VPExceptions.GenericFailure(
                    message = exception.message ?: "Unknown internal error",
                    className = OpenID4VP::class.simpleName.orEmpty()
                ).toErrorResponse()
            }.apply {
                authorizationRequest?.state?.takeIf { it.isNotBlank() }?.let {
                    this[OpenID4VPErrorFields.STATE] = it
                }
            }

            val networkResponse = sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = errorPayload,
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
            val verifierResponse = toVerifierResponse(networkResponse)
            (exception as? OpenID4VPExceptions)?.setVerifierResponse(verifierResponse)
            return verifierResponse
        } catch (err: Exception) {
            throw OpenID4VPExceptions.ErrorDispatchFailure(
                message = "Failed to send error to verifier: ${err.message}",
                className = className
            )
        }
    }

    internal fun constructAndSendAuthorizationResponseToVerifier(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        responseUri: String,
    ): VerifierResponse {
        val authorizationResponse: AuthorizationResponse = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = reconstructSigningResults(vpTokenSigningResults)
        )

        val networkResponse = sendAuthorizationResponse(
            authorizationResponse = authorizationResponse,
            responseUri = responseUri,
            authorizationRequest = authorizationRequest
        )
        return toVerifierResponse(networkResponse)
    }

    private fun constructAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
    ): Map<String, String> {
        val authorizationResponse: AuthorizationResponse = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        return ResponseModeBasedHandlerFactory.get(authorizationRequest.responseMode!!)
            .getAuthorizationResponse(
                authorizationRequest,
                authorizationResponse,
                walletNonce,
                walletMetadata
            )
    }


    private fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
    ): AuthorizationResponse {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                return if (authorizationRequest is AuthorizationPresentationExchangeRequest) {
                    val (vpToken, presentationSubmission) = createVPTokenAndPresentationSubmission(
                        vpTokenSigningResults,
                        authorizationRequest,
                        unsignedVPTokenResults,
                        formatToCredentialInputDescriptorMapping
                    )
                    AuthorizationResponse.PresentationExchange(
                        presentationSubmission = presentationSubmission,
                        vpToken = vpToken,
                        state = authorizationRequest.state
                    )
                } else {
                    AuthorizationResponse.Dcql(
                        vpToken = emptyMap(),
                        state = authorizationRequest.state
                    )
                }
            }

            else -> throw OpenID4VPExceptions.InvalidData(
                "Provided response_type - ${authorizationRequest.responseType} is not supported",
                className
            )
        }
    }

    private fun reconstructSigningResults(
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<FormatType, List<VPTokenSigningResult>> {
        return constructSigningResults(
            unsignedVPTokenResults = unsignedVPTokenResults,
            signingResults = vpTokenSigningResults,
            className = className
        )
    }

    private fun sendAuthorizationResponse(
        authorizationResponse: AuthorizationResponse,
        responseUri: String,
        authorizationRequest: AuthorizationRequest,
    ): NetworkResponse {
        return ResponseModeBasedHandlerFactory.get(authorizationRequest.responseMode!!)
            .sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUri,
                authorizationResponse = authorizationResponse,
                walletNonce = walletNonce,
                walletMetadata = walletMetadata
            )
    }

    private fun createVPTokenAndPresentationSubmission(
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
        authorizationRequest: AuthorizationRequest,
        unsignedVPTokenResults: Map<FormatType, Pair<Any?, List<UnsignedVPToken>>>,
        formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>
    ): Pair<VPTokenType, PresentationSubmission> {
        if (unsignedVPTokenResults.keys != vpTokenSigningResults.keys) {
            throw OpenID4VPExceptions.InvalidData(
                message = "VPTokenSigningResult not provided for the required formats",
                className = className
            )
        }

        val finalVpTokens: MutableList<VPToken> = mutableListOf()
        val finalDescriptorMappings: MutableList<DescriptorMap> = mutableListOf()
        var rootIndex = 0


        formatToCredentialInputDescriptorMapping.forEach { (credentialFormat, credentialInputDescriptorMappings) ->
            val vpTokenSigningResultsForFormat = (vpTokenSigningResults[credentialFormat]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "unable to find the related credential format - $credentialFormat in the vpTokenSigningResults map",
                    className
                ))
            val unsignedVPTokenResult = unsignedVPTokenResults[credentialFormat]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "unable to find the related credential format - $credentialFormat in the unsignedVPTokenResults map",
                    className
                )
            val vpTokenBuilder = VPTokenFactory.getVPTokenBuilder(credentialFormat)

            val (vpTokens, descriptorMaps, nextRootIndex) = vpTokenBuilder.build(
                credentialInputDescriptorMappings,
                unsignedVPTokenResult,
                vpTokenSigningResultsForFormat,
                rootIndex
            )
            finalVpTokens.addAll(vpTokens)
            finalDescriptorMappings.addAll(descriptorMaps)

            rootIndex = nextRootIndex
        }

        val vpToken = (finalVpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenElement(it[0]) }
            ?: VPTokenArray(finalVpTokens))

        sanitizeDescriptorMap(finalDescriptorMappings, finalVpTokens.size == 1)
        val definitionId = (authorizationRequest as? AuthorizationPresentationExchangeRequest)?.presentationDefinition?.id ?: ""
        val presentationSubmission = PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = definitionId,
            descriptorMap = finalDescriptorMappings,
        )

        return Pair(vpToken, presentationSubmission)
    }

    private fun sanitizeDescriptorMap(
        descriptorMaps: MutableList<DescriptorMap>,
        isSingleVPToken: Boolean
    ) {
        if (isSingleVPToken) {
            descriptorMaps.forEach { descriptorMap ->
                val updatedRootPath = descriptorMap.path.replace(Regex("""\[\d+]"""), "")
                val updatedDescriptorMap = descriptorMap.copy(
                    path = updatedRootPath,
                    pathNested = descriptorMap.pathNested
                )
                descriptorMaps[descriptorMaps.indexOf(descriptorMap)] = updatedDescriptorMap
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun createUnsignedVPTokens(
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?,
        credentialsMap: Map<String, Map<FormatType, List<Any>>>
    ): Map<FormatType, Pair<Any?, List<UnsignedVPToken>>> {
        createFormatToCredentialInputDescriptorMapping(credentialsMap)

        val specVersion: SpecVersion =
            if (authorizationRequest is AuthorizationPresentationExchangeRequest) SpecVersion.DRAFT_23
            else SpecVersion.V1

        return this.formatToCredentialInputDescriptorMapping.mapValues { (format, credentialInputDescriptorMappings) ->
            when (format) {
                FormatType.LDP_VC -> {
                    UnsignedLdpVPTokenBuilder(
                        authorizationRequest = authorizationRequest,
                        specVersion = specVersion,
                        id = UUIDGenerator.generateUUID(),
                        holder = holderId ?: "",
                        signatureSuite = signatureSuite ?: "Ed25519Signature2020",
                        walletMetadata = walletMetadata
                    ).build(credentialInputDescriptorMappings)
                }

                FormatType.MSO_MDOC -> {
                    UnsignedMdocVPTokenBuilder(
                        authorizationRequest = authorizationRequest,
                        specVersion = specVersion,
                        responseUri = responseUri,
                        mdocGeneratedNonce = walletNonce,
                        walletMetadata = walletMetadata
                    ).build(credentialInputDescriptorMappings)
                }

                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
                    UnsignedSdJwtVPTokenBuilder(
                        authorizationRequest = authorizationRequest,
                        specVersion = specVersion,
                        walletMetadata = walletMetadata
                    ).build(credentialInputDescriptorMappings)
                }
            }
        }
    }

    private fun createFormatToCredentialInputDescriptorMapping(matchingCredentials: Map<String, Map<FormatType, List<Any>>>) {
        val formatToCredentialInputDescriptorMapping =
            mutableMapOf<FormatType, MutableList<CredentialInputDescriptorMapping>>()

        for ((inputDescriptorId, formatCredentialMap) in matchingCredentials) {
            for ((format, credentialsArray) in formatCredentialMap) {
                credentialsArray.forEach { credential ->
                    val mapping = CredentialInputDescriptorMapping(
                        credential = credential,
                        format = format,
                        inputDescriptorId = inputDescriptorId
                    )
                    formatToCredentialInputDescriptorMapping.getOrPut(format) { mutableListOf() }
                        .add(mapping)
                }
            }
        }
        this.formatToCredentialInputDescriptorMapping = formatToCredentialInputDescriptorMapping
    }

    private fun toVerifierResponse(networkResponse: NetworkResponse): VerifierResponse {
        val redirectUriKey = "redirect_uri"

        val jsonElement = runCatching { Json.parseToJsonElement(networkResponse.body) }.getOrNull()
        val jsonObject = jsonElement as? JsonObject
        val redirectUri =
            runCatching { jsonObject?.get(redirectUriKey)?.jsonPrimitive?.contentOrNull }.getOrNull()
        val additionalParams = jsonObject?.toMutableMap()?.apply { remove(redirectUriKey) }
            ?.let { Json.encodeToString(JsonObject.serializer(), JsonObject(it)) }
            ?: networkResponse.body

        return VerifierResponse(
            networkResponse.statusCode,
            redirectUri,
            additionalParams,
            networkResponse.headers,
            networkResponse.body
        )
    }
}
