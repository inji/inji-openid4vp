package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
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

private const val className = "UnsignedMdocVPTokenBuilder"

internal class UnsignedMdocVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val responseUri: String,
    private val mdocGeneratedNonce: String,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {
    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Any?, List<UnsignedVPToken>> {
        val docTypeToDeviceAuthenticationBytes = mutableMapOf<String, String>()
        val docTypeToMapping = mutableMapOf<String, CredentialInputDescriptorMapping>()

        val openId4VPHandover: DataItem = MdocSpecVersionHandler.from(specVersion)
            .buildOpenID4VPHandover(
                authorizationRequest = authorizationRequest,
                mdocGeneratedNonce = mdocGeneratedNonce,
                responseUri = responseUri,
                walletConfig = walletConfig
            )

        val sessionTranscript: DataItem = cborArrayOf(null, null, openId4VPHandover)

        val deviceNamespaces: DataItem = cborMapOf()
        val deviceNameSpacesBytes = tagEncodedCbor(deviceNamespaces)

        credentialInputDescriptorMappings.map { credentialInputDescriptorMapping ->
            val mdocCredential = credentialInputDescriptorMapping.credential as? String
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
            if (docTypeToDeviceAuthenticationBytes.containsKey(docType)) {
                throw OpenID4VPExceptions.InvalidData(
                    "Duplicate Mdoc Credentials with same doctype found",
                    className
                )
            }
            docTypeToDeviceAuthenticationBytes[docType] =
                encodeCbor(deviceAuthenticationBytes).toHex()
            credentialInputDescriptorMapping.identifier = docType
            docTypeToMapping[docType] = credentialInputDescriptorMapping
        }

        val unsignedVPTokens = credentialInputDescriptorMappings
            .map { mapping ->
                val docType = mapping.identifier
                    ?: throw OpenID4VPExceptions.InvalidData(
                        "Missing docType for mdoc credential",
                        className
                    )
                val bytesToSign = docTypeToDeviceAuthenticationBytes[docType]!!
                val (keyRef, alg) = resolveMdocKeyAndAlg(mapping.credential as String, className)

                UnsignedVPToken(
                    format = FormatType.MSO_MDOC,
                    holderKeyReference = keyRef,
                    signatureAlgorithm = alg,
                    dataToSign = hexToByteArray(bytesToSign)
                )
            }

        return Pair(docTypeToDeviceAuthenticationBytes, unsignedVPTokens)
    }

    // TODO: Add method func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping])

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
                    val clientIdHash = createHashedDataItem(authorizationRequest.clientId, mdocGeneratedNonce)
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
