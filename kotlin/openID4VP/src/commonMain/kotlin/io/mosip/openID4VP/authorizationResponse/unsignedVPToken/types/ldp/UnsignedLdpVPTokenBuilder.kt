package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.JsonWebSignature2020

typealias VPTokenSigningPayload = LdpVPToken

private const val LDP_INTERNAL_PATH = "verifiableCredential"
private const val CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
private const val CREDENTIALS_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1"
private const val ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"
private const val JWS_2020_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1"
private const val CONTEXT_KEY = "@context"
private const val VERIFIABLE_PRESENTATION_TYPE = "VerifiablePresentation"

private val SIGNATURE_SUITE_CONTEXTS = mapOf(
    Ed25519Signature2020.value to ED25519_2020_CONTEXT,
    JsonWebSignature2020.value to JWS_2020_CONTEXT
)

internal class UnsignedLdpVPTokenBuilder(
    private val id: String,
    private val holder: String,
    private val challenge: String,
    private val domain: String,
    private val signatureSuite: String
) : UnsignedVPTokenBuilder {
    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<VPTokenSigningPayload?, UnsignedVPToken> {
        val verifiableCredentials = mutableListOf<Any>()

        credentialInputDescriptorMappings.forEachIndexed { index, credentialInputDescriptorMapping ->
            verifiableCredentials.add(credentialInputDescriptorMapping.credential)
            credentialInputDescriptorMapping.nestedPath = formatNestedPath(index)
        }

        val credentialsContext = extractCredentialContexts(verifiableCredentials)
        val context = buildContextList(credentialsContext)

        val vpTokenSigningPayload = VPTokenSigningPayload(
            context = context,
            type = listOf(VERIFIABLE_PRESENTATION_TYPE),
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            proof = Proof(
                type = signatureSuite,
                created = formattedCurrentDateTime(),
                verificationMethod = holder,
                domain = domain,
                challenge = challenge
            )
        )

        val vpTokenSigningPayloadString = encodeToJsonString(
            vpTokenSigningPayload,
            "vpTokenSigningPayload",
            VPTokenSigningPayload::class.java.simpleName
        )

        val dataToSign = URDNA2015Canonicalization.canonicalize(vpTokenSigningPayloadString)
        val unsignedLdpVPToken = UnsignedLdpVPToken(dataToSign = dataToSign)

        return Pair(vpTokenSigningPayload, unsignedLdpVPToken)
    }

    private fun formatNestedPath(index: Int): String = "$.$LDP_INTERNAL_PATH[$index]"

    private fun extractCredentialContexts(verifiableCredentials: List<Any>): Set<String> {
        return verifiableCredentials.mapNotNull { vc ->
            val credentialMap = vc as? Map<*, *>
            val contextArray = credentialMap?.get(CONTEXT_KEY) as? List<*>
            contextArray?.firstOrNull()?.toString()
        }.toSet()
    }

    private fun buildContextList(credentialsContext: Set<String>): List<String> {
        val context = mutableListOf(CREDENTIALS_V2_CONTEXT)

        SIGNATURE_SUITE_CONTEXTS[signatureSuite]?.let { context.add(it) }

        return context
    }
}