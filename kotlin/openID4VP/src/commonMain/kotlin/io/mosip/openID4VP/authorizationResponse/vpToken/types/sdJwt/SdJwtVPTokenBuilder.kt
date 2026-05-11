package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = SdJwtVPTokenBuilder::class.java.simpleName

internal class SdJwtVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<SdJwtVPToken>, List<DescriptorMap>, Int> {
        val uuidToUnsignedKBJWT = extractUuidToUnsignedKBT(unsignedVPTokenResult)
        val signingResultsIterator = vpTokenSigningResults.iterator()
        var vpIndex = rootIndex
        val vpTokens = mutableListOf<SdJwtVPToken>()
        val descriptorMaps = mutableListOf<DescriptorMap>()

        credentialInputDescriptorMappings.forEach { mapping ->
            val uuid = extractUUID(mapping.identifier)
            val sdJwtCredential = extractSdJwtString(mapping.credential)
            val unsignedKBJwt = uuidToUnsignedKBJWT[uuid]
            val finalVPToken = buildFinalToken(uuid, sdJwtCredential, unsignedKBJwt, signingResultsIterator)

            vpTokens.add(SdJwtVPToken(finalVPToken))
            descriptorMaps.add(
                DescriptorMap(
                    id = mapping.inputDescriptorId,
                    format = mapping.format.value,
                    path = createDescriptorMapPath(vpIndex),
                    pathNested = createNestedPath(mapping.inputDescriptorId, mapping.nestedPath, mapping.format)
                )
            )
            vpIndex++
        }

        assertNoExtraSigningResults(signingResultsIterator)
        return Triple(vpTokens, descriptorMaps, vpIndex)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>> {
        val uuidToUnsignedKBJWT = extractUuidToUnsignedKBT(unsignedVPTokenResult)
        val vpTokenResult = mutableMapOf<String, MutableList<VPToken>>()
        val signingResultsIterator = vpTokenSigningResults.iterator()

        credentialToCredentialQueryIdMappings.forEach { mapping ->
            val uuid = extractUUID(mapping.identifier)
            val sdJwtCredential = extractSdJwtString(mapping.credential)
            val unsignedKBJwt = uuidToUnsignedKBJWT[uuid]
            val finalVPToken = buildFinalToken(uuid, sdJwtCredential, unsignedKBJwt, signingResultsIterator)

            vpTokenResult.getOrPut(mapping.credentialQueryId) { mutableListOf() }
                .add(SdJwtVPToken(finalVPToken))
        }

        assertNoExtraSigningResults(signingResultsIterator)
        return vpTokenResult
    }

    @Suppress("UNCHECKED_CAST")
    private fun extractUuidToUnsignedKBT(
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>
    ): Map<String, String> {
        return unsignedVPTokenResult.first as? Map<String, String>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected uuidToUnsignedKBJWT map as payload",
                className
            )
    }

    private fun extractUUID(identifier: String?): String {
        return identifier ?: throw OpenID4VPExceptions.InvalidData(
            "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
            className
        )
    }

    private fun extractSdJwtString(credential: Any): String {
        return credential as? String ?: throw OpenID4VPExceptions.InvalidData(
            "SD-JWT credential is not a String",
            className
        )
    }

    private fun buildFinalToken(
        uuid: String,
        sdJwtCredential: String,
        unsignedKBJwt: String?,
        signingResultsIterator: Iterator<VPTokenSigningResult>
    ): String {
        if (unsignedKBJwt == null) {
            return sdJwtCredential
        }
        if (!signingResultsIterator.hasNext()) {
            throw OpenID4VPExceptions.MissingInput(
                "",
                "Missing Key Binding JWT signature for uuid: $uuid",
                className
            )
        }
        val signature = encodeToBase64Url(signingResultsIterator.next().signedData)
        if (signature.isEmpty()) {
            throw OpenID4VPExceptions.MissingInput(
                "",
                "Missing Key Binding JWT signature for uuid: $uuid",
                className
            )
        }
        return "$sdJwtCredential$unsignedKBJwt.$signature"
    }

    private fun assertNoExtraSigningResults(iterator: Iterator<VPTokenSigningResult>) {
        if (iterator.hasNext()) {
            throw OpenID4VPExceptions.InvalidData(
                "Extra SD-JWT signing results provided",
                className
            )
        }
    }
}
