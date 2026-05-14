package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.LdpVcToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToMultibaseBase58btc
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = LdpVPTokenBuilder::class.simpleName!!

internal class LdpVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<VPToken>, List<DescriptorMap>, Int> {
        if (vpTokenSigningResults.isEmpty()) {
            throw OpenID4VPExceptions.MissingInput(
                "",
                "Missing LDP signature",
                className
            )
        }
        if (vpTokenSigningResults.size > 1) {
            throw OpenID4VPExceptions.InvalidData(
                "Extra LDP signing results provided",
                className
            )
        }

        val vpTokenSigningResult = vpTokenSigningResults.first()
        val unsignedVPToken = unsignedVPTokenResult.second.first()
        val ldpVPToken = unsignedVPTokenResult.first as? LdpVPToken
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected LdpVPToken as payload",
                className
            )

        val result = buildVPToken(ldpVPToken, vpTokenSigningResult, unsignedVPToken)

        val descriptorMaps = credentialInputDescriptorMappings.map { mapping ->
            DescriptorMap(
                id = mapping.inputDescriptorId,
                format = VPFormatType.LDP_VP.value,
                path = "$[$rootIndex]",
                pathNested = createNestedPath(
                    mapping.inputDescriptorId,
                    mapping.nestedPath,
                    FormatType.LDP_VC
                )
            )
        }
        return Triple(listOf(result), descriptorMaps, rootIndex + 1)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Any?, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>> {
        val signingResultsIterator = vpTokenSigningResults.iterator()
        val unsignedVPTokenIterator = unsignedVPTokenResult.second.iterator()
        val vpTokenResult = mutableMapOf<String, MutableList<VPToken>>()

        @Suppress("UNCHECKED_CAST")
        val payloadMap = unsignedVPTokenResult.first as? Map<String, Any>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected Map<String, Any> as payload for DCQL LDP flow",
                className
            )

        for (mapping in credentialToCredentialQueryIdMappings) {
            val identifier = mapping.identifier
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Missing identifier in credential mapping", className
                )

            val payload = payloadMap[identifier]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "No payload found for identifier: $identifier", className
                )

            val vpToken: VPToken = when (payload) {
                is LdpVPToken -> {
                    if (!signingResultsIterator.hasNext()) {
                        throw OpenID4VPExceptions.MissingInput("", "Missing LDP signature", className)
                    }
                    val signingResult = signingResultsIterator.next()
                    val unsignedVPToken = if (unsignedVPTokenIterator.hasNext()) unsignedVPTokenIterator.next() else null
                    buildVPToken(payload, signingResult, unsignedVPToken)
                }
                is LdpVcToken -> payload
                else -> throw OpenID4VPExceptions.InvalidData(
                    "Unexpected payload type: ${payload::class.simpleName}", className
                )
            }

            vpTokenResult.getOrPut(mapping.credentialQueryId) { mutableListOf() }
                .add(vpToken)
        }

        return vpTokenResult
    }

    private fun buildVPToken(
        ldpVPToken: LdpVPToken,
        vpTokenSigningResult: VPTokenSigningResult,
        unsignedVPToken: UnsignedVPToken?
    ): LdpVPToken {
        val proof = ldpVPToken.proof!!
        val proofType = proof.type

        when (proofType) {
            SignatureSuiteAlgorithm.JsonWebSignature2020.value,
            SignatureSuiteAlgorithm.Ed25519Signature2018.value -> {
                val signingInputBytes = unsignedVPToken?.dataToSign
                    ?: throw OpenID4VPExceptions.InvalidData("Missing unsigned VP token data", className)
                val dotIndex = signingInputBytes.indexOf(0x2E.toByte())
                val headerBase64Url = String(signingInputBytes.sliceArray(0 until dotIndex))
                val signatureBase64Url = encodeToBase64Url(vpTokenSigningResult.signedData)
                proof.jws = "$headerBase64Url..$signatureBase64Url"
            }
            SignatureSuiteAlgorithm.RSASignature2018.value -> {
                val signatureBase64Url = encodeToBase64Url(vpTokenSigningResult.signedData)
                proof.signatureValue = signatureBase64Url
            }
            else -> {
                proof.proofValue = encodeToMultibaseBase58btc(vpTokenSigningResult.signedData)
            }
        }

        return LdpVPToken(
            ldpVPToken.context,
            ldpVPToken.type,
            ldpVPToken.verifiableCredential,
            ldpVPToken.id,
            ldpVPToken.holder,
            proof
        )
    }
}
