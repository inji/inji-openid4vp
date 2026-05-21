package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
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
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.openID4VP.wallet.Credential
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
    private lateinit var formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>
    private var dcqlCredentialMappings: List<CredentialToCredentialQueryIdMapping> = emptyList()

    internal fun constructUnsignedVPToken(
        selectedCredentials: Map<String, List<Credential>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        nonce: String
    ): List<UnsignedVPToken> {
        try {
            val unsupportedFormats = selectedCredentials.values.flatten()
                .map { it.format }
                .filterNot { it == FormatType.MSO_MDOC || it == FormatType.DC_SD_JWT || it == FormatType.VC_SD_JWT || it == FormatType.LDP_VC }
                .distinct()
            if (unsupportedFormats.isNotEmpty()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Unsigned VP token construction supports only SD-JWT, mdoc, and LDP credentials. Unsupported formats: ${unsupportedFormats.joinToString { it.value }}",
                    className
                )
            }

            val allCredentials = selectedCredentials.values.flatten()
            if (allCredentials.isEmpty()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
                    className
                )
            }

            walletNonce = nonce

            val specVersion: SpecVersion =
                if (authorizationRequest is AuthorizationPresentationExchangeRequest) SpecVersion.DRAFT_23
                else SpecVersion.V1

            if (authorizationRequest is AuthorizationDcqlRequest) {
                dcqlCredentialMappings = selectedCredentials.flatMap { (credentialQueryId, credentials) ->
                    credentials.map { credential ->
                        CredentialToCredentialQueryIdMapping(
                            format = credential.format,
                            credential = credential.data,
                            credentialQueryId = credentialQueryId
                        )
                    }
                }
                this.unsignedVPTokenResults = createUnsignedVPTokensForDcql(
                    authorizationRequest = authorizationRequest,
                    responseUri = responseUri
                )
            } else {
                val formatToMappings = mutableMapOf<FormatType, MutableList<CredentialInputDescriptorMapping>>()
                for ((inputDescriptorId, credentials) in selectedCredentials) {
                    for (credential in credentials) {
                        val mapping = CredentialInputDescriptorMapping(
                            format = credential.format,
                            credential = credential.data,
                            inputDescriptorId = inputDescriptorId
                        )
                        formatToMappings.getOrPut(credential.format) { mutableListOf() }
                            .add(mapping)
                    }
                }
                this.formatToCredentialInputDescriptorMapping = formatToMappings

                val results = mutableMapOf<FormatType, Pair<Any?, List<UnsignedVPToken>>>()
                for ((format, credentialInputDescriptorMappings) in formatToMappings) {
                    val result = when (format) {
                        FormatType.LDP_VC -> {
                            UnsignedLdpVPTokenBuilder(
                                authorizationRequest = authorizationRequest,
                                specVersion = specVersion,
                                id = UUIDGenerator.generateUUID(),
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
                    results[format] = result
                }
                this.unsignedVPTokenResults = results
            }

            return unsignedVPTokenResults.keys
                .sortedBy { it.value }
                .flatMap { format ->
                    unsignedVPTokenResults[format]!!.second
                }
        } catch (exception: OpenID4VPExceptions) {
            throw exception
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.VerifiablePresentationConstructionFailure(exception, className)
        }
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

    internal fun constructVPResponse(
        vpTokenSigningResults: List<VPTokenSigningResult>,
        authorizationRequest: AuthorizationRequest,
    ): Map<String, String> {
        try {
            val reconstructedResults = reconstructSigningResults(vpTokenSigningResults)
            return constructAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = reconstructedResults
            )
        } catch (exception: OpenID4VPExceptions) {
            throw exception
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.AuthorizationResponseConstructionFailure(exception, className)
        }
    }

    internal fun constructAndSendAuthorizationResponseToVerifier(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        responseUri: String,
    ): VerifierResponse {
        val authorizationResponse: AuthorizationResponse = try {
            createAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = reconstructSigningResults(vpTokenSigningResults)
            )
        } catch (exception: OpenID4VPExceptions) {
            throw exception
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.AuthorizationResponseConstructionFailure(exception, className)
        }
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
                    val vpTokensResult = createDcqlVPToken(
                        vpTokenSigningResults = vpTokenSigningResults,
                        unsignedVPTokenResults = unsignedVPTokenResults,
                        dcqlCredentialMappings = dcqlCredentialMappings
                    )
                    AuthorizationResponse.Dcql(
                        vpToken = vpTokensResult,
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

    private fun createDcqlVPToken(
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
        unsignedVPTokenResults: Map<FormatType, Pair<Any?, List<UnsignedVPToken>>>,
        dcqlCredentialMappings: List<CredentialToCredentialQueryIdMapping>
    ): Map<String, List<VPToken>> {
        if (unsignedVPTokenResults.keys != vpTokenSigningResults.keys) {
            throw OpenID4VPExceptions.InvalidData(
                "VPTokenSigningResult not provided for the required formats",
                className
            )
        }

        val credentialMappingsByFormat = dcqlCredentialMappings.groupBy { it.format }
        val finalVpTokens = mutableMapOf<String, MutableList<VPToken>>()

        for ((credentialFormat, mappings) in credentialMappingsByFormat) {
            val vpTokenSigningResultsForFormat = vpTokenSigningResults[credentialFormat]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "unable to find the related credential format - $credentialFormat in the vpTokenSigningResults map",
                    className
                )
            val unsignedVPTokenResult = unsignedVPTokenResults[credentialFormat]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "unable to find the related credential format - $credentialFormat in the unsignedVPTokenResults map",
                    className
                )

            val vpTokenBuilder = VPTokenFactory.getVPTokenBuilder(credentialFormat)
            val vpTokenResult = vpTokenBuilder.build(
                credentialToCredentialQueryIdMappings = mappings,
                unsignedVPTokenResult = unsignedVPTokenResult,
                vpTokenSigningResults = vpTokenSigningResultsForFormat
            )

            for ((key, newValue) in vpTokenResult) {
                finalVpTokens.getOrPut(key) { mutableListOf() }.addAll(newValue)
            }
        }

        return finalVpTokens
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

    private fun createUnsignedVPTokensForDcql(
        authorizationRequest: AuthorizationDcqlRequest,
        responseUri: String
    ): Map<FormatType, Pair<Any?, List<UnsignedVPToken>>> {
        val dcqlMappingsByFormat = dcqlCredentialMappings.groupBy { it.format }
        val results = mutableMapOf<FormatType, Pair<Any?, List<UnsignedVPToken>>>()

        for ((format, mappings) in dcqlMappingsByFormat) {
            val mutableMappings = mappings.toMutableList()
            val result: Pair<Any?, List<UnsignedVPToken>> = when (format) {
                FormatType.LDP_VC -> {
                    UnsignedLdpVPTokenBuilder(
                        authorizationRequest = authorizationRequest,
                        specVersion = SpecVersion.V1,
                        id = UUIDGenerator.generateUUID(),
                        walletMetadata = walletMetadata
                    ).buildDcql(mutableMappings)
                }

                FormatType.MSO_MDOC -> {
                    val peMappings = mappings.map {
                        CredentialInputDescriptorMapping(it.format, it.credential, it.credentialQueryId)
                    }
                    val builderResult = UnsignedMdocVPTokenBuilder(
                        authorizationRequest = authorizationRequest,
                        specVersion = SpecVersion.V1,
                        responseUri = responseUri,
                        mdocGeneratedNonce = walletNonce,
                        walletMetadata = walletMetadata
                    ).build(peMappings)
                    peMappings.forEachIndexed { i, pe -> mappings[i].identifier = pe.identifier }
                    builderResult
                }

                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
                    val peMappings = mappings.map {
                        CredentialInputDescriptorMapping(it.format, it.credential, it.credentialQueryId)
                    }
                    val builderResult = UnsignedSdJwtVPTokenBuilder(
                        authorizationRequest = authorizationRequest,
                        specVersion = SpecVersion.V1,
                        walletMetadata = walletMetadata
                    ).build(peMappings)
                    peMappings.forEachIndexed { i, pe -> mappings[i].identifier = pe.identifier }
                    builderResult
                }
            }
            results[format] = result
        }

        return results
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
