package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.getVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.cose.CoseSignature1Utils
import io.mosip.openID4VP.common.MdocCredentialUtils.getMdocDocTypeAndIssuerSigned
import io.mosip.openID4VP.common.MdocCredentialUtils.extractMdocKeyReferenceAndAlg
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.taggedCbor24
import co.nstant.`in`.cbor.model.Map as CborMap

private val className = MdocVPTokenBuilder::class.java.simpleName

internal class MdocVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<MdocVPToken>, List<DescriptorMap>, Int> {
        val documents = mutableListOf<DataItem>()
        val descriptorMaps = mutableListOf<DescriptorMap>()

        credentialInputDescriptorMappings.forEach { mapping ->
            val document =
                buildDocument(mapping.identifier, mapping.credential, vpTokenSigningResults)
            documents.add(document)

            descriptorMaps.add(
                DescriptorMap(
                    id = mapping.inputDescriptorId,
                    format = mapping.format.value,
                    path = createDescriptorMapPath(rootIndex),
                    pathNested = createNestedPath(
                        mapping.inputDescriptorId,
                        mapping.nestedPath,
                        mapping.format
                    )
                )
            )
        }

        val mdocVPToken = buildMdocVPToken(cborArrayOf(*documents.toTypedArray()))

        return Triple(listOf(mdocVPToken), descriptorMaps, rootIndex + 1)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>> {
        val vpTokenResult = mutableMapOf<String, MutableList<VPToken>>()

        credentialToCredentialQueryIdMappings.forEach { credentialToCredentialQueryIdMapping ->
            val document = buildDocument(
                credentialToCredentialQueryIdMapping.identifier,
                credentialToCredentialQueryIdMapping.credential,
                vpTokenSigningResults
            )
            val mdocVPToken = buildMdocVPToken(cborArrayOf(document))

            vpTokenResult.getOrPut(credentialToCredentialQueryIdMapping.credentialQueryId) { mutableListOf() }
                .add(mdocVPToken)
        }

        return vpTokenResult
    }

    private fun buildDocument(
        identifier: String?,
        credential: Any,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): CborMap {
        val vPTokenSigningResult =
            getVPTokenSigningResult(vpTokenSigningResults, identifier, className)

        val (mdocCredential, docType, issuerSigned) = getMdocDocTypeAndIssuerSigned(
            credential,
            className
        )

        val document =
            CborMap().apply {
                put(UnicodeString("issuerSigned"), issuerSigned)
                put(UnicodeString("docType"), UnicodeString(docType))
            }
        val (_, alg) = extractMdocKeyReferenceAndAlg(mdocCredential, className)

        val deviceAuthentication = DeviceAuthentication(
            signature = vPTokenSigningResult.signedData,
            algorithm = alg
        )
        deviceAuthentication.validate()

        val deviceSignature = createDeviceSignature(alg, vPTokenSigningResult.signedData)
        val deviceAuth = cborMapOf("deviceSignature" to deviceSignature)
        val deviceSigned = cborMapOf(
            "deviceAuth" to deviceAuth,
            "nameSpaces" to getDeviceNamespacesBytes()
        )
        document.put(UnicodeString("deviceSigned"), deviceSigned)
        return document
    }

    private fun buildMdocVPToken(document: DataItem): MdocVPToken {
        val response = cborMapOf(
            "version" to "1.0",
            "documents" to document,
            "status" to 0
        )
        val mdocVPToken = MdocVPToken(encodeToBase64Url(encodeCbor(response)))
        return mdocVPToken
    }

    private fun createDeviceSignature(
        signingAlgorithm: String,
        signature: ByteArray
    ): DataItem {
        return CoseSignature1Utils.createCoseSign1(signingAlgorithm, signature)
    }

    private fun getDeviceNamespacesBytes(): ByteString {
        return taggedCbor24(CborMap())
    }

}
