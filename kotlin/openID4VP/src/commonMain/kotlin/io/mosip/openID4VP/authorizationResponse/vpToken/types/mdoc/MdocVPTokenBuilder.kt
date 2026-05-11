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
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<MdocVPToken>, List<DescriptorMap>, Int> {
        @Suppress("UNCHECKED_CAST")
        val docTypeToDeviceAuthenticationBytes = unsignedVPTokenResult.first as? Map<String, String>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected docTypeToDeviceAuthenticationBytes map as payload",
                className
            )

        val signingResultsIterator = vpTokenSigningResults.iterator()

        val documents = mutableListOf<DataItem>()
        val descriptorMaps = mutableListOf<DescriptorMap>()

        val orderedMappings = credentialInputDescriptorMappings.map { mapping ->
            val docType = mapping.identifier
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Missing docType for mdoc credential",
                    className
                )
            if (!docTypeToDeviceAuthenticationBytes.containsKey(docType)) {
                throw OpenID4VPExceptions.InvalidData(
                    "No device authentication payload for docType $docType",
                    className
                )
            }
            docType to mapping
        }

        orderedMappings.forEach { (docType, mapping) ->
            if (!signingResultsIterator.hasNext()) {
                throw OpenID4VPExceptions.MissingInput(
                    "",
                    "Device authentication signature not found for mdoc credential docType $docType",
                    className
                )
            }

            val signingResult = signingResultsIterator.next()

            val mdocCredential = mapping.credential as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "MDOC credential is not a String",
                    className
                )

            val document = getDecodedMdocCredential(mdocCredential)

            val (_, alg) = resolveMdocKeyAndAlg(mdocCredential, className)

            val deviceAuthentication = DeviceAuthentication(
                signature = signingResult.signedData,
                algorithm = alg
            )
            deviceAuthentication.validate()

            val deviceSignature = createDeviceSignature(alg, signingResult.signedData)

            val deviceNamespacesBytes = tagEncodedCbor(cborMapOf())
            val deviceAuth = cborMapOf("deviceSignature" to deviceSignature)
            val deviceSigned = cborMapOf(
                "deviceAuth" to deviceAuth,
                "nameSpaces" to deviceNamespacesBytes
            )

            document.put(UnicodeString("deviceSigned"), deviceSigned)
            documents.add(document)
            descriptorMaps.add(
                DescriptorMap(
                    id = mapping.inputDescriptorId,
                    format = mapping.format.value,
                    path = createDescriptorMapPath(rootIndex),
                    pathNested = createNestedPath(mapping.inputDescriptorId, mapping.nestedPath, mapping.format)
                )
            )
        }

        if (signingResultsIterator.hasNext()) {
            throw OpenID4VPExceptions.InvalidData(
                "Extra mdoc signing results provided",
                className
            )
        }

        val response = cborMapOf(
            "version" to "1.0",
            "documents" to cborArrayOf(*documents.toTypedArray()),
            "status" to 0
        )
        val mdocVPToken = MdocVPToken(encodeToBase64Url(encodeCbor(response)))

        return Triple(listOf(mdocVPToken), descriptorMaps, rootIndex + 1)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>> {
        @Suppress("UNCHECKED_CAST")
        val docTypeToDeviceAuthenticationBytes = unsignedVPTokenResult.first as? Map<String, String>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected docTypeToDeviceAuthenticationBytes map as payload",
                className
            )

        val signingResultsIterator = vpTokenSigningResults.iterator()
        val vpTokenResult = mutableMapOf<String, MutableList<VPToken>>()

        for (docTypeString in docTypeToDeviceAuthenticationBytes.keys.sorted()) {
            if (!signingResultsIterator.hasNext()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Missing signing result for $docTypeString",
                    className
                )
            }
            val signingResult = signingResultsIterator.next()

            val matchingMapping = credentialToCredentialQueryIdMappings.firstOrNull { mapping ->
                val cred = mapping.credential as? String ?: return@firstOrNull false
                val decoded = getDecodedMdocCredential(cred)
                val dt = decoded[UnicodeString("docType")]
                dt is UnicodeString && dt.string == docTypeString
            } ?: throw OpenID4VPExceptions.InvalidData(
                "No credential mapping found for docType $docTypeString",
                className
            )

            val mdocCredential = matchingMapping.credential as? String
                ?: throw OpenID4VPExceptions.InvalidData("MDOC credential is not a String", className)

            val document = getDecodedMdocCredential(mdocCredential)
            val (_, alg) = resolveMdocKeyAndAlg(mdocCredential, className)

            val deviceAuthentication = DeviceAuthentication(
                signature = signingResult.signedData,
                algorithm = alg
            )
            deviceAuthentication.validate()

            val deviceSignature = createDeviceSignature(alg, signingResult.signedData)
            val deviceNamespacesBytes = tagEncodedCbor(cborMapOf())
            val deviceAuth = cborMapOf("deviceSignature" to deviceSignature)
            val deviceSigned = cborMapOf(
                "deviceAuth" to deviceAuth,
                "nameSpaces" to deviceNamespacesBytes
            )
            document.put(UnicodeString("deviceSigned"), deviceSigned)

            val response = cborMapOf(
                "version" to "1.0",
                "documents" to cborArrayOf(document),
                "status" to 0
            )
            val mdocVPToken = MdocVPToken(encodeToBase64Url(encodeCbor(response)))

            vpTokenResult.getOrPut(matchingMapping.credentialQueryId) { mutableListOf() }
                .add(mdocVPToken)
        }

        if (signingResultsIterator.hasNext()) {
            throw OpenID4VPExceptions.InvalidData("Extra mdoc signing results provided", className)
        }

        return vpTokenResult
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
