package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.common.LdpKeyResolver
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2018
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.JsonWebSignature2020
import io.mosip.openID4VP.constants.SpecVersion

private const val LDP_INTERNAL_PATH = "verifiableCredential"
private const val className = "UnsignedLdpVPTokenBuilder"

internal class UnsignedLdpVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val id: String,
    private val holder: String,
    private val signatureSuite: String,
    override val walletMetadata: WalletMetadata? = null
) : UnsignedVPTokenBuilder {
    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Any?, List<UnsignedVPToken>> {
        val context = mutableListOf("https://www.w3.org/2018/credentials/v1")

        if (signatureSuite == Ed25519Signature2020.value) {
            context.add("https://w3id.org/security/suites/ed25519-2020/v1")
        }
        if (signatureSuite == JsonWebSignature2020.value) {
            context.add("https://w3id.org/security/suites/jws-2020/v1")
        }

        val verifiableCredentials = mutableListOf<Any>()

        credentialInputDescriptorMappings.forEachIndexed { index, credentialInputDescriptorMapping ->
            verifiableCredentials.add(credentialInputDescriptorMapping.credential)
            credentialInputDescriptorMapping.nestedPath = "$.$LDP_INTERNAL_PATH[$index]"
        }

        val vpTokenSigningPayload = LdpVPToken(
            context = context,
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            proof = Proof(
                type = signatureSuite,
                created = formattedCurrentDateTime(),
                verificationMethod = holder,
                domain = authorizationRequest.clientId,
                challenge = authorizationRequest.nonce
            )
        )

        val vpTokenSigningPayloadString = encodeToJsonString(
            vpTokenSigningPayload,
            "vpTokenSigningPayload",
            LdpVPToken::class.java.simpleName
        )

        val cryptoAlgorithm = LdpKeyResolver.resolveJWSAlgorithm(holder)

        val canonicalDataBase64Url = URDNA2015Canonicalization.canonicalize(vpTokenSigningPayloadString)

        val dataToSign: ByteArray = when (signatureSuite) {
            JsonWebSignature2020.value, Ed25519Signature2018.value -> {
                val headerMap = mapOf(
                    "alg" to cryptoAlgorithm,
                    "crit" to listOf("b64"),
                    "b64" to false
                )
                val headerJson = encodeToJsonString(headerMap, "jwsHeader", className)
                val headerBase64Url = encodeToBase64Url(headerJson.toByteArray(Charsets.UTF_8))
                val rawPayloadBytes = decodeFromBase64Url(canonicalDataBase64Url)
                headerBase64Url.toByteArray(Charsets.UTF_8) + byteArrayOf(0x2E.toByte()) + rawPayloadBytes
            }
            else -> decodeFromBase64Url(canonicalDataBase64Url)
        }

        val unsignedVPToken = UnsignedVPToken(
            format = FormatType.LDP_VC,
            holderKeyReference = holder,
            signatureAlgorithm = cryptoAlgorithm,
            dataToSign = dataToSign
        )

        return Pair(vpTokenSigningPayload, listOf(unsignedVPToken))
    }
}
