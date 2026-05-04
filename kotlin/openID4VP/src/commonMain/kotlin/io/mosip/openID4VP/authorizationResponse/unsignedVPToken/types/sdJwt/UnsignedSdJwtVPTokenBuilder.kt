package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.hashData
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.security.PublicKey
import java.util.Date
import kotlin.collections.get

internal class UnsignedSdJwtVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    override val walletMetadata: WalletMetadata? = null
) : UnsignedVPTokenBuilder {

    companion object {
        private const val className = "UnsignedSdJwtVPTokenBuilder"
        private const val KEY_BINDING_JWT = "kb+jwt"
    }

    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<VPTokenSigningPayload?, UnsignedVPToken> {
        val uuidToUnsignedKBJWT = mutableMapOf<String, String>()

        credentialInputDescriptorMappings.forEach { credentialInputDescriptorMapping ->
            val uuid = UUIDGenerator.generateUUID()
            credentialInputDescriptorMapping.identifier = uuid
            val sdJwtCredential =
                credentialInputDescriptorMapping.credential as? String ?: throw InvalidData(
                    "SD-JWT credential is not a String",
                    className
                )

            val sdJwt = sdJwtCredential.split("~")[0]
            val sdJwtPayload = JWSHandler.extractDataJsonFromJws(sdJwt, JWSHandler.JwsPart.PAYLOAD)

            val confirmationKeyClaim = sdJwtPayload["cnf"] as? Map<*, *>
            if (!confirmationKeyClaim.isNullOrEmpty()) {
                val jwtSigningAlgorithm: String

                if ("kid" in confirmationKeyClaim.keys) {
                    val kid = confirmationKeyClaim["kid"] as? String
                        ?: throw InvalidData("kid must be a string", className)
                    val didResolver = DidPublicKeyResolver()
                    val confirmationKey = didResolver.resolve(kid.trimEnd('='), null)
                    jwtSigningAlgorithm = mapKeyAlgorithmToJwtAlg(confirmationKey)
                } else {
                    throw UnsupportedOperationException("Unsupported cnf format, only 'kid' is supported")
                }

                val jwtHeader = mapOf(
                    "alg" to jwtSigningAlgorithm,
                    "typ" to KEY_BINDING_JWT
                )

                val sdHashAlgorithm = sdJwtPayload["_sd_alg"] as? String ?: "SHA-256"
                val sdHash = hashData(sdJwtCredential, sdHashAlgorithm)

                val jwtPayload = mapOf(
                    "iat" to (Date().time / 1000),
                    "aud" to authorizationRequest.clientId,
                    "nonce" to authorizationRequest.nonce,
                    "sd_hash" to sdHash
                )

                val unsignedJwt = JWSHandler.createUnsignedJWS(jwtHeader, jwtPayload)
                uuidToUnsignedKBJWT[uuid] = unsignedJwt
            }
        }
        return Pair(null, UnsignedSdJwtVPToken(uuidToUnsignedKBJWT))
    }

    private fun mapKeyAlgorithmToJwtAlg(key: PublicKey): String {
        return when (key.algorithm) {
            "Ed25519" -> "EdDSA"
            "EC" -> "ES256" //for es256K support we need to distinguish based on curve name.
            "RSA" -> "RS256"
            else -> throw InvalidData("Unsupported key algorithm: ${key.algorithm}", className)
        }
    }

}
