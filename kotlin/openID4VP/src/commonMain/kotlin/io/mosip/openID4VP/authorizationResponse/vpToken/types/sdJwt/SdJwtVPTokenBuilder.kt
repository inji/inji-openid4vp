package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.getVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = SdJwtVPTokenBuilder::class.java.simpleName

internal class SdJwtVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<SdJwtVPToken>, List<DescriptorMap>, Int> {
        val identifierToUnsignedKBT = extractIdentifierToUnsignedKBT(unsignedVPTokenResult)
        var vpIndex = rootIndex
        val vpTokens = mutableListOf<SdJwtVPToken>()
        val descriptorMaps = mutableListOf<DescriptorMap>()

        credentialInputDescriptorMappings.forEach { mapping ->
            val identifier = extractUUID(mapping.identifier)
            val sdJwtCredential = extractSdJwtString(mapping.credential)
            val unsignedKBJwt = identifierToUnsignedKBT[identifier]
            val finalVPToken = buildFinalToken(identifier, sdJwtCredential, unsignedKBJwt, vpTokenSigningResults)

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

        return Triple(vpTokens, descriptorMaps, vpIndex)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>> {
        val identifierToUnsignedKBT = extractIdentifierToUnsignedKBT(unsignedVPTokenResult)
        val vpTokenResult = mutableMapOf<String, MutableList<VPToken>>()

        credentialToCredentialQueryIdMappings.forEach { mapping ->
            val uuid = extractUUID(mapping.identifier)
            val sdJwtCredential = extractSdJwtString(mapping.credential)
            val unsignedKBJwt = identifierToUnsignedKBT[uuid]
            val finalVPToken = buildFinalToken(uuid, sdJwtCredential, unsignedKBJwt, vpTokenSigningResults)

            vpTokenResult.getOrPut(mapping.credentialQueryId) { mutableListOf() }
                .add(SdJwtVPToken(finalVPToken))
        }

        return vpTokenResult
    }

    @Suppress("UNCHECKED_CAST")
    private fun extractIdentifierToUnsignedKBT(
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>
    ): Map<String, String> {
        return unsignedVPTokenResult.first as? Map<String, String>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected identifierToUnsignedKBJWT map as payload",
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
        identifier: String,
        sdJwtCredential: String,
        unsignedKBJwt: String?,
        signingResults: List<VPTokenSigningResult>
    ): String {
        if (unsignedKBJwt == null) {
            return sdJwtCredential
        }
        val vPTokenSigningResult = getVPTokenSigningResult(signingResults, identifier, className)

        val signature = encodeToBase64Url(vPTokenSigningResult.signedData)
        if (signature.isEmpty()) {
            throw OpenID4VPExceptions.MissingInput(
                "",
                "Missing signing result signature for id: $identifier",
                className
            )
        }

        return "$sdJwtCredential$unsignedKBJwt.$signature"
    }
}
