package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
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
import io.mosip.openID4VP.constants.SpecVersion

typealias VPTokenSigningPayload = LdpVPToken

private const val LDP_INTERNAL_PATH = "verifiableCredential"

internal class UnsignedLdpVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val id: String,
    private val holder: String,
    private val signatureSuite: String,
    override val walletMetadata: WalletMetadata? = null
) : UnsignedVPTokenBuilder {
    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<VPTokenSigningPayload?, UnsignedVPToken> {
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

        val vpTokenSigningPayload = VPTokenSigningPayload(
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
            VPTokenSigningPayload::class.java.simpleName
        )

        val dataToSign =
            URDNA2015Canonicalization.canonicalize(vpTokenSigningPayloadString)
        val unsignedLdpVPToken = UnsignedLdpVPToken(dataToSign = dataToSign)

        return Pair(vpTokenSigningPayload, unsignedLdpVPToken)
    }
}