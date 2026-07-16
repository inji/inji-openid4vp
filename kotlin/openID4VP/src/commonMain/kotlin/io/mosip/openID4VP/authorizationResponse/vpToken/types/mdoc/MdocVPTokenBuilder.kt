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
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.mapSigningAlgorithmToProtectedAlg
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.resolveMdocKeyAndAlg
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

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
    ): co.nstant.`in`.cbor.model.Map {
        val vPTokenSigningResult =
            getVPTokenSigningResult(vpTokenSigningResults, identifier, className)

        val mdocCredential = credential as? String
            ?: throw OpenID4VPExceptions.InvalidData("MDOC credential is not a String", className)

        val document = getDecodedMdocCredential(mdocCredential)
        val (_, alg) = resolveMdocKeyAndAlg(mdocCredential, className)

        val deviceAuthentication = DeviceAuthentication(
            signature = vPTokenSigningResult.signedData,
            algorithm = alg
        )
        deviceAuthentication.validate()

        val deviceSignature = createDeviceSignature(alg, vPTokenSigningResult.signedData)
        val deviceNamespacesBytes = tagEncodedCbor(cborMapOf())
        val deviceAuth = cborMapOf("deviceSignature" to deviceSignature)
        val deviceSigned = cborMapOf(
            "deviceAuth" to deviceAuth,
            "nameSpaces" to deviceNamespacesBytes
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
        val cborEncodedSignature = encodeCbor(ByteString(signature))

        val protectedSigningAlgorithm = mapSigningAlgorithmToProtectedAlg(signingAlgorithm)

        val protectedHeader = encodeCbor(cborMapOf(1 to protectedSigningAlgorithm))
        val unprotectedHeader = cborMapOf()

        return cborArrayOf(protectedHeader, unprotectedHeader, null, cborEncodedSignature)
    }
}
