package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = SdJwtVPTokenBuilder::class.java.simpleName

internal class SdJwtVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<SdJwtVPToken>, List<DescriptorMap>, Int> {
        @Suppress("UNCHECKED_CAST")
        val uuidToUnsignedKBJWT = unsignedVPTokenResult.first as? Map<String, String>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected uuidToUnsignedKBJWT map as payload",
                className
            )

        val signingResultsIterator = vpTokenSigningResults.iterator()
        var vpIndex = rootIndex
        val vpTokens = mutableListOf<SdJwtVPToken>()
        val descriptorMaps = mutableListOf<DescriptorMap>()

        credentialInputDescriptorMappings.forEach { mapping ->
            val uuid = mapping.identifier ?: throw OpenID4VPExceptions.InvalidData(
                "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
                className
            )
            val sdJwtCredential = mapping.credential as? String ?: throw OpenID4VPExceptions.InvalidData(
                "SD-JWT credential is not a String",
                className
            )
            val unsignedKBJwt = uuidToUnsignedKBJWT[uuid]
            val signature = if (unsignedKBJwt != null) {
                if (!signingResultsIterator.hasNext()) {
                    throw OpenID4VPExceptions.MissingInput(
                        "",
                        "Missing Key Binding JWT signature for uuid: $uuid",
                        className
                    )
                }
                signingResultsIterator.next().signedData
            } else {
                null
            }

            val finalVPToken = when {
                unsignedKBJwt == null && signature == null -> {
                    sdJwtCredential
                }
                unsignedKBJwt != null && signature != null -> {
                    "$sdJwtCredential$unsignedKBJwt.$signature"
                }
                unsignedKBJwt != null && signature == null -> {
                    throw OpenID4VPExceptions.MissingInput(
                        "",
                        "Missing Key Binding JWT signature for uuid: $uuid",
                        className
                    )
                }
                else -> {
                    throw OpenID4VPExceptions.InvalidData(
                        "Signature present but unsigned KB-JWT missing for uuid: $uuid",
                        className,
                    )
                }
            }
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

        if (signingResultsIterator.hasNext()) {
            throw OpenID4VPExceptions.InvalidData(
                "Extra SD-JWT signing results provided",
                className
            )
        }

        return Triple(vpTokens, descriptorMaps, vpIndex)
    }
}
