package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.MdocCredentialUtils.getMdocDocType
import io.mosip.openID4VP.common.MdocCredentialUtils.resolveMdocKeyAndAlg
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.createHashedDataItem
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.generateHash
import io.mosip.openID4VP.common.tagEncodedCbor2
import io.mosip.openID4VP.common.toJWKThumbprintBstr
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import java.io.ByteArrayOutputStream
import co.nstant.`in`.cbor.model.Map as CborMap


private const val className = "UnsignedMdocVPTokenBuilder"

internal class UnsignedMdocVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val responseUri: String,
    private val mdocGeneratedNonce: String,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {
    @JvmName("buildForPex")
    fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Map<String, ByteArray>, List<UnsignedVPToken>> {
        val uuidToDeviceAuthenticationBytes = mutableMapOf<String, ByteArray>()

        val sessionTranscript = getSessionTranscript()
        val deviceNameSpacesBytes = getDeviceNamespacesBytes()
        val existingDocTypes = mutableSetOf<String>()

        credentialInputDescriptorMappings.forEach { credentialInputDescriptorMapping ->
            buildPayloadAndUnsignedVPToken(
                credential = credentialInputDescriptorMapping.credential,
                sessionTranscript = sessionTranscript,
                deviceNameSpacesBytes = deviceNameSpacesBytes,
                uuidToDeviceAuthenticationBytes = uuidToDeviceAuthenticationBytes,
                setIdentifier = { identifier ->
                    credentialInputDescriptorMapping.identifier = identifier
                },
                existingDocTypes = existingDocTypes
            )
        }

        val unsignedVPTokens = credentialInputDescriptorMappings
            .map { mapping ->
                getUnsignedVPToken(
                    mapping.identifier,
                    mapping.credential,
                    uuidToDeviceAuthenticationBytes
                )
            }

        return Pair(uuidToDeviceAuthenticationBytes, unsignedVPTokens)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>
    ): Pair<Map<String, ByteArray>, List<UnsignedVPToken>> {
        val uuidToDeviceAuthenticationBytes = mutableMapOf<String, ByteArray>()

        val sessionTranscript: DataItem = getSessionTranscript()
        val deviceNameSpacesBytes: ByteString = getDeviceNamespacesBytes()
        val existingDocTypes = mutableSetOf<String>()

        credentialToCredentialQueryIdMappings.forEach { credentialToCredentialQueryIdMapping ->
            buildPayloadAndUnsignedVPToken(
                credential = credentialToCredentialQueryIdMapping.credential,
                sessionTranscript = sessionTranscript,
                deviceNameSpacesBytes = deviceNameSpacesBytes,
                uuidToDeviceAuthenticationBytes = uuidToDeviceAuthenticationBytes,
                setIdentifier = { identifier ->
                    credentialToCredentialQueryIdMapping.identifier = identifier
                },
                existingDocTypes = existingDocTypes
            )
        }

        val unsignedVPTokens = credentialToCredentialQueryIdMappings
            .map { mapping ->
                getUnsignedVPToken(
                    mapping.identifier,
                    mapping.credential,
                    uuidToDeviceAuthenticationBytes
                )
            }

        return Pair(uuidToDeviceAuthenticationBytes, unsignedVPTokens)
    }

    private fun getUnsignedVPToken(
        identifier: String?,
        credential: Any,
        uuidToDeviceAuthenticationBytes: Map<String, ByteArray>
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
            dataToSign = bytesToSign
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
        val sessionTranscript = cborArrayOf(null, null, openId4VPHandover)
        println("Session transcript - $sessionTranscript")
        println("Session transcript b64 ${encodeToBase64Url(encodeCbor(sessionTranscript))}")
        return sessionTranscript
    }

    // DeviceNameSpacesBytes = #6.24(bstr .cbor emptyMap)
    private fun getDeviceNamespacesBytes(): ByteString {
        val emptyMap = CborMap()

        val inner = ByteArrayOutputStream()
        CborEncoder(inner).encode(emptyMap)


        val bstr = ByteString(inner.toByteArray())
        bstr.setTag(24)


//        val outer = ByteArrayOutputStream()
//        CborEncoder(outer).encode(bstr)
//
//        return outer.toByteArray()
        return bstr
    }

    private fun buildPayloadAndUnsignedVPToken(
        credential: Any,
        sessionTranscript: DataItem,
        deviceNameSpacesBytes: ByteString,
        uuidToDeviceAuthenticationBytes: MutableMap<String, ByteArray>,
        setIdentifier: (String) -> Unit,
        existingDocTypes: MutableSet<String>
    ) {
        val mdocCredential = credential as? String
            ?: throw OpenID4VPExceptions.InvalidData(
                "MDOC credential is not a String",
                className
            )
        val docType = (getMdocDocType(mdocCredential, className))

        val deviceAuthentication: DataItem = cborArrayOf(
            "DeviceAuthentication",
            (sessionTranscript),
            UnicodeString(docType),
            deviceNameSpacesBytes
        )
        // Encode DeviceAuthentication array as plain CBOR bytes for signing per mdoc spec.
        // Only deviceNameSpaces within the array has the #6.24 tag; the array itself should not.
        val deviceAuthenticationBytes = tagEncodedCbor2(deviceAuthentication)
        println("deviceNameSpacesBytes = " + encodeToBase64Url(deviceNameSpacesBytes.bytes))
        println("deviceAuthenticationBytes = " + encodeToBase64Url(deviceAuthenticationBytes))

        if (existingDocTypes.contains(docType)) {
            throw OpenID4VPExceptions.InvalidData(
                "Duplicate Mdoc Credentials with same doctype found",
                className
            )
        }

        existingDocTypes.add(docType)

        val identifier = UUIDGenerator.generateUUID()
        // Build the protected header (Map with alg: -7 for ES256)
        val protectedHeaderMap = cborMapOf(
            1 to -7
        )
        val protectedHeaderBytes = encodeCbor(protectedHeaderMap)
        val protectedHeaderBstr = ByteString(protectedHeaderBytes)

// Build the Sig_structure array
        val sigStructure = cborArrayOf(
            "Signature1",
            protectedHeaderBstr,
            ByteString(ByteArray(0)), // empty external_aad
            ByteString(deviceAuthenticationBytes) // Your properly built #6.24 array bytes
        )

// THIS is what you send to JS to be signed
        val bytesToSign = encodeCbor(sigStructure)
        uuidToDeviceAuthenticationBytes[identifier] = bytesToSign
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
            val handoverInfo = when (this) {
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
                    println("verifier public key $verifierPublicKey")
                    val thumbprintDataItem: DataItem? = verifierPublicKey?.let {
                        toJWKThumbprintBstr(it)
                    }

                    val openId4VPHandoverInfo: DataItem = cborArrayOf(
                        authorizationRequest.clientId,
                        authorizationRequest.nonce,
                        thumbprintDataItem,
                        responseUri
                    )
                    println("openId4VPHandoverInfo $openId4VPHandoverInfo")
                    val openID4VPHandoverInfoBytes = (encodeCbor(openId4VPHandoverInfo))
                    println("openID4VPHandoverInfoBytes $openID4VPHandoverInfoBytes")
                    val handoverInfoHash = ByteString(generateHash(openID4VPHandoverInfoBytes))
                    println("handoverInfoHash $handoverInfoHash")
                    println("ovp Handover info b64 ${encodeToBase64Url(handoverInfoHash.bytes)}")
                    println(
                        "ovp Handover info b64 ${
                            encodeToBase64Url(
                                encodeCbor(
                                    openId4VPHandoverInfo
                                )
                            )
                        }"
                    )
                    cborArrayOf("OpenID4VPHandover", handoverInfoHash)
                }
            }
            println("Handover info $handoverInfo")
            println("Handover info b64 ${encodeToBase64Url(encodeCbor(handoverInfo))}")
            return handoverInfo
        }
    }
}
