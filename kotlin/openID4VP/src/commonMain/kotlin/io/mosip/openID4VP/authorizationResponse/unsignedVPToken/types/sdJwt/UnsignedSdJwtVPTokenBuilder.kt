package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.hashData
import io.mosip.openID4VP.common.resolveSdJwtKeyAndAlg
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import java.util.Date

internal class UnsignedSdJwtVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {

    companion object {
        private const val className = "UnsignedSdJwtVPTokenBuilder"
        private const val KEY_BINDING_JWT = "kb+jwt"
    }

    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Any?, List<UnsignedVPToken>> {
        val uuidToUnsignedKBJWT = mutableMapOf<String, String>()
        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()

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
                val hasKid = "kid" in confirmationKeyClaim.keys
                val hasJwk = "jwk" in confirmationKeyClaim.keys

                if (!hasKid && !hasJwk) {
                    throw UnsupportedOperationException("Unsupported cnf format, must contain 'kid' or 'jwk'")
                }

                if (hasKid) {
                    confirmationKeyClaim["kid"] as? String
                        ?: throw InvalidData("kid must be a string", className)
                }

                val (holderKeyReference, jwtSigningAlgorithm) = resolveSdJwtKeyAndAlg(sdJwtCredential, className)

                val jwtHeader = mutableMapOf<String, Any>(
                    "alg" to jwtSigningAlgorithm,
                    "typ" to KEY_BINDING_JWT
                )

                if (hasJwk) {
                    val jwkMap = confirmationKeyClaim["jwk"] as? Map<*, *>
                    if (jwkMap != null) {
                        jwtHeader["jwk"] = jwkMap
                    }
                }

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

                unsignedVPTokens.add(UnsignedVPToken(
                    format = credentialInputDescriptorMapping.format,
                    holderKeyReference = holderKeyReference,
                    signatureAlgorithm = jwtSigningAlgorithm,
                    dataToSign = unsignedJwt.toByteArray(Charsets.UTF_8)
                ))
            }
        }

        return Pair(uuidToUnsignedKBJWT, unsignedVPTokens)
    }
}
