package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.common.LdpKeyResolver
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2018
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.JsonWebSignature2020
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private const val LDP_INTERNAL_PATH = "verifiableCredential"
private const val className = "UnsignedLdpVPTokenBuilder"

internal class UnsignedLdpVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val id: String,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {

    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Any?, List<UnsignedVPToken>> {
        if (credentialInputDescriptorMappings.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData("No credentials provided for LDP VP Token", className)
        }

        val vpTokenSigningPayloads = mutableListOf<LdpVPToken>()
        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()

        credentialInputDescriptorMappings.forEach { mapping ->
            mapping.nestedPath = "$.$LDP_INTERNAL_PATH[0]"
            val (extractedHolder, extractedSuite) = extractHolderAndSignatureSuite(mapping.credential)
            val sanitizedHolder = sanitizeHolderId(extractedHolder)

            val (vpPayload, unsignedTokens) = buildPayloadAndUnsignedVPToken(
                verifiableCredentials = listOf(mapping.credential),
                signatureSuite = extractedSuite,
                holder = sanitizedHolder
            )
            vpTokenSigningPayloads.add(
                vpPayload as? LdpVPToken
                    ?: throw OpenID4VPExceptions.InvalidData("Expected LdpVPToken as payload", className)
            )
            unsignedVPTokens.addAll(unsignedTokens)
        }

        return Pair(vpTokenSigningPayloads, unsignedVPTokens)
    }

    fun buildDcql(
        credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>
    ): Pair<Map<String, Any>, List<UnsignedVPToken>> {
        val dcqlRequest = authorizationRequest as? AuthorizationDcqlRequest
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected AuthorizationDcqlRequest for DCQL flow", className
            )

        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()
        val vpTokenSigningPayloads = mutableMapOf<String, Any>()

        credentialToCredentialQueryIdMappings.forEachIndexed { index, mapping ->
            val uuid = UUIDGenerator.generateUUID()
            mapping.identifier = uuid

            val credentialQueryId = mapping.credentialQueryId
            val credential = mapping.credential

            val matchedQuery = dcqlRequest.dcqlQuery.credentials.firstOrNull { it.id == credentialQueryId }
                ?: throw OpenID4VPExceptions.InvalidData(
                    "No matching credential query found for credential query id: $credentialQueryId",
                    className
                )

            if (!matchedQuery.requireCryptographicHolderBinding) {
                vpTokenSigningPayloads[uuid] = LdpVcToken(credential)
                return@forEachIndexed
            }

            val (extractedHolder, extractedSuite) = extractHolderAndSignatureSuite(credential)
            val sanitizedHolder = sanitizeHolderId(extractedHolder)

            val (vpPayload, tokens) = buildPayloadAndUnsignedVPToken(
                verifiableCredentials = listOf(credential),
                signatureSuite = extractedSuite,
                holder = sanitizedHolder
            )
            vpTokenSigningPayloads[uuid] = vpPayload ?: LdpVcToken(credential)
            unsignedVPTokens.addAll(tokens)
        }

        return Pair(vpTokenSigningPayloads, unsignedVPTokens)
    }

    private fun buildPayloadAndUnsignedVPToken(
        verifiableCredentials: List<Any>,
        signatureSuite: String,
        holder: String
    ): Pair<Any?, List<UnsignedVPToken>> {
        val context = mutableListOf("https://www.w3.org/2018/credentials/v1")

        if (signatureSuite == Ed25519Signature2020.value) {
            context.add("https://w3id.org/security/suites/ed25519-2020/v1")
        }
        if (signatureSuite == JsonWebSignature2020.value) {
            context.add("https://w3id.org/security/suites/jws-2020/v1")
        }

        val vpTokenSigningPayload = LdpVPToken(
            context = context,
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            proof = Proof(
                type = signatureSuite,
                challenge = authorizationRequest.nonce,
                domain = authorizationRequest.clientId,
                verificationMethod = holder
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

    companion object {
        @Suppress("UNCHECKED_CAST")
        internal fun extractHolderAndSignatureSuite(credential: Any): Pair<String, String> {
            val credentialMap = credential as? Map<String, Any>
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Credential is not a valid JSON object", className
                )

            val credentialSubject = credentialMap["credentialSubject"] as? Map<String, Any>
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Holder ID not available in the credential", className
                )

            val holderId = credentialSubject["id"] as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Holder ID not available in the credential", className
                )

            return Pair(holderId, SignatureSuiteAlgorithm.JsonWebSignature2020.value)
        }

        internal fun sanitizeHolderId(holderId: String): String {
            return holderId
                .replace("+", "-")
                .replace("/", "_")
                .replace("=", "") + "#0"
        }
    }
}

@JsonSerialize(using = LdpVcTokenSerializer::class)
internal data class LdpVcToken(val verifiableCredential: Any) : VPToken

internal class LdpVcTokenSerializer : JsonSerializer<LdpVcToken>() {
    override fun serialize(value: LdpVcToken, gen: JsonGenerator, serializers: SerializerProvider) {
        serializers.defaultSerializeValue(value.verifiableCredential, gen)
    }
}
