package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToMultibaseBase58btc
import io.mosip.openID4VP.common.validateField
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

        val proof = ldpVPToken.proof!!
        val proofType = proof.type

        when (proofType) {
            SignatureSuiteAlgorithm.JsonWebSignature2020.value,
            SignatureSuiteAlgorithm.Ed25519Signature2018.value -> {
                require(vpTokenSigningResult.signedData != "null" && validateField(vpTokenSigningResult.signedData, "String")) {
                    throw OpenID4VPExceptions.InvalidInput(
                        fieldPath = listOf("LdpVPTokenBuilder", "jws"),
                        className = className,
                        fieldType = "String"
                    )
                }
                val signingInputBytes = decodeFromBase64Url(unsignedVPToken.dataToSign)
                val dotIndex = signingInputBytes.indexOf(0x2E.toByte())
                val headerBase64Url = String(signingInputBytes.sliceArray(0 until dotIndex))
                proof.jws = "$headerBase64Url..${vpTokenSigningResult.signedData}"
            }
            SignatureSuiteAlgorithm.RSASignature2018.value -> {
                require(vpTokenSigningResult.signedData != "null" && validateField(vpTokenSigningResult.signedData, "String")) {
                    throw OpenID4VPExceptions.InvalidInput(
                        fieldPath = listOf("LdpVPTokenBuilder", "jws"),
                        className = className,
                        fieldType = "String"
                    )
                }
                proof.jws = vpTokenSigningResult.signedData
            }
            else -> {
                require(vpTokenSigningResult.signedData != "null" && validateField(vpTokenSigningResult.signedData, "String")) {
                    throw OpenID4VPExceptions.InvalidInput(
                        fieldPath = listOf("LdpVPTokenBuilder", "proofValue"),
                        className = className,
                        fieldType = "String"
                    )
                }
                proof.proofValue = encodeToMultibaseBase58btc(vpTokenSigningResult.signedData)
            }
        }

        val ldpVPTokenResult = LdpVPToken(
            ldpVPToken.context,
            ldpVPToken.type,
            ldpVPToken.verifiableCredential,
            ldpVPToken.id,
            ldpVPToken.holder,
            proof
        )
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
        return Triple(listOf(ldpVPTokenResult), descriptorMaps, rootIndex + 1)
    }
}
