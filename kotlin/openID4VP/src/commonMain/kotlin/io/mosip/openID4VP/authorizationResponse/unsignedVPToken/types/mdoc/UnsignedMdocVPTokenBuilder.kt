package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.createHashedDataItem
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.generateHash
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.hexToByteArray
import io.mosip.openID4VP.common.toJWKThumbprintBstr
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.common.toHex
import io.mosip.openID4VP.common.resolveMdocKeyAndAlg
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import co.nstant.`in`.cbor.model.ByteString
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.common.UUIDGenerator

private const val className = "UnsignedMdocVPTokenBuilder"

internal class UnsignedMdocVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val responseUri: String,
    private val mdocGeneratedNonce: String,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {
    @JvmName("buildForPex")
    fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Map<String, String>, List<UnsignedVPToken>> {
        val uuidToDeviceAuthenticationBytes = mutableMapOf<String, String>()

        val sessionTranscript = getSessionTranscript()
        val deviceNameSpacesBytes = getDeviceNamespacesBytes()
        val existingDocTypes = mutableSetOf<String>()

        credentialInputDescriptorMappings.forEach { credentialInputDescriptorMapping ->
            buildPayloadAndUnsignedVPToken(
                credential = credentialInputDescriptorMapping.credential,
                sessionTranscript = sessionTranscript,
                deviceNameSpacesBytes = deviceNameSpacesBytes,
                uuidToDeviceAuthenticationBytes = uuidToDeviceAuthenticationBytes,
                setIdentifier = { identifier -> credentialInputDescriptorMapping.identifier = identifier },
                existingDocTypes = existingDocTypes
            )
        }

        val unsignedVPTokens = credentialInputDescriptorMappings
            .map { mapping ->
                getUnsignedVPToken(mapping.identifier, mapping.credential, uuidToDeviceAuthenticationBytes)
            }

        return Pair(uuidToDeviceAuthenticationBytes, unsignedVPTokens)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>
    ): Pair<Map<String, String>, List<UnsignedVPToken>> {
        val uuidToDeviceAuthenticationBytes = mutableMapOf<String, String>()

        val sessionTranscript = getSessionTranscript()
        val deviceNameSpacesBytes = getDeviceNamespacesBytes()
        val existingDocTypes = mutableSetOf<String>()

        credentialToCredentialQueryIdMappings.forEach { credentialToCredentialQueryIdMapping ->
            buildPayloadAndUnsignedVPToken(
                credential = credentialToCredentialQueryIdMapping.credential,
                sessionTranscript = sessionTranscript,
                deviceNameSpacesBytes = deviceNameSpacesBytes,
                uuidToDeviceAuthenticationBytes = uuidToDeviceAuthenticationBytes,
                setIdentifier = { identifier -> credentialToCredentialQueryIdMapping.identifier = identifier },
                existingDocTypes = existingDocTypes
            )
        }

        val unsignedVPTokens = credentialToCredentialQueryIdMappings
            .map { mapping ->
                getUnsignedVPToken(mapping.identifier, mapping.credential, uuidToDeviceAuthenticationBytes)
            }

        return Pair(uuidToDeviceAuthenticationBytes, unsignedVPTokens)
    }

    private fun getUnsignedVPToken(
        identifier: String?,
        credential: Any,
        uuidToDeviceAuthenticationBytes: Map<String, String>
    ): UnsignedVPToken {
        val identifier = identifier
            ?: throw OpenID4VPExceptions.InvalidData(
                "Missing docType for mdoc credential",
                className
            )
        val bytesToSign = uuidToDeviceAuthenticationBytes[identifier]
            ?: throw OpenID4VPExceptions.InvalidData(
                "Missing bytes to sign for mdoc credential",
                className
            )
        val (keyRef, alg) = resolveMdocKeyAndAlg(credential as String, className)

        return UnsignedVPToken(
            id = identifier,
            format = FormatType.MSO_MDOC,
            holderKeyReference = keyRef,
            signatureAlgorithm = alg,
            dataToSign = hexToByteArray(bytesToSign)
        )
    }

    private fun getSessionTranscript(): DataItem {
        val openId4VPHandover = MdocSpecVersionHandler.from(specVersion)
            .buildOpenID4VPHandover(
                authorizationRequest = authorizationRequest,
                mdocGeneratedNonce = mdocGeneratedNonce,
                responseUri = responseUri,
                walletConfig = walletConfig
            )
        return cborArrayOf(null, null, openId4VPHandover)
    }

    private fun getDeviceNamespacesBytes(): DataItem {
        val deviceNamespaces: DataItem = cborMapOf()
        return tagEncodedCbor(deviceNamespaces)
    }

    private fun buildPayloadAndUnsignedVPToken(
        credential: Any,
        sessionTranscript: DataItem,
        deviceNameSpacesBytes: DataItem,
        uuidToDeviceAuthenticationBytes: MutableMap<String, String>,
        setIdentifier: (String) -> Unit,
        existingDocTypes: MutableSet<String>
    ) {
        val mdocCredential = credential as? String
            ?: throw OpenID4VPExceptions.InvalidData(
                "MDOC credential is not a String",
                className
            )
        val decodedMdocCredential = getDecodedMdocCredential(mdocCredential)
        val docType = decodedMdocCredential.get(UnicodeString("docType")).toString()

        val deviceAuthentication: DataItem = cborArrayOf(
            "DeviceAuthentication",
            sessionTranscript,
            docType,
            deviceNameSpacesBytes
        )
        val deviceAuthenticationBytes = tagEncodedCbor(deviceAuthentication)

        if (existingDocTypes.contains(docType)) {
            throw OpenID4VPExceptions.InvalidData(
                "Duplicate Mdoc Credentials with same doctype found",
                className
            )
        }

        existingDocTypes.add(docType)

        val identifier = UUIDGenerator.generateUUID()
        uuidToDeviceAuthenticationBytes[identifier] = encodeCbor(deviceAuthenticationBytes).toHex()
        setIdentifier(identifier)
    }

    private sealed class MdocSpecVersionHandler {
        object Draft23 : MdocSpecVersionHandler()
        object SpecV1 : MdocSpecVersionHandler()

        companion object {
            fun from(specVersion: SpecVersion): MdocSpecVersionHandler {
                return if (specVersion == SpecVersion.V1) SpecV1 else Draft23
            }
        }

        fun buildOpenID4VPHandover(
            authorizationRequest: AuthorizationRequest,
            mdocGeneratedNonce: String,
            responseUri: String,
            walletConfig: WalletConfig
        ): DataItem {
            return when (this) {
                is Draft23 -> {
                    val clientIdHash =
                        createHashedDataItem(authorizationRequest.clientId, mdocGeneratedNonce)
                    val responseUriHash = createHashedDataItem(responseUri, mdocGeneratedNonce)
                    cborArrayOf(clientIdHash, responseUriHash, authorizationRequest.nonce)
                }

                is SpecV1 -> {
                    val responseHandler = ResponseModeBasedHandlerFactory.get(
                        authorizationRequest.responseMode ?: ""
                    )
                    val verifierPublicKey = responseHandler.getVerifierPublicKeyForEncryption(
                        authorizationRequest, walletConfig
                    )
                    val thumbprintDataItem: DataItem? = verifierPublicKey?.let {
                        toJWKThumbprintBstr(it)
                    }

                    val openId4VPHandoverInfo = cborArrayOf(
                        authorizationRequest.clientId,
                        authorizationRequest.nonce,
                        thumbprintDataItem,
                        responseUri
                    )
                    val handoverInfoHash = ByteString(generateHash(openId4VPHandoverInfo))
                    cborArrayOf("OpenID4VPHandover", handoverInfoHash)
                }
            }
        }
    }
}
