package io.mosip.openID4VP.jwt.jwe.encryption

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = EncryptionProvider::class.simpleName!!
object EncryptionProvider {

    private val supportedEncryptionAlgs = setOf(
        EncryptionAlgorithm.ECDH_ES.value
    )

    fun getEncrypter(jwk: Jwk): JWEEncrypter {
        if (jwk.alg !in supportedEncryptionAlgs) {
            throw OpenID4VPExceptions.JweEncryptionFailure(
                "Unsupported JWE algorithm: ${jwk.alg}",
                className
            )
        }

        return when (jwk.kty) {
            KeyType.OKP.value -> {
                if (jwk.crv != Curve.X25519.name) {
                    throw OpenID4VPExceptions.JweEncryptionFailure(
                        "Unsupported OKP curve for ECDH-ES: ${jwk.crv}. Only X25519 is supported.",
                        className
                    )
                }

                X25519Encrypter(getPublicOctetKey(jwk))
            }

            KeyType.EC.value -> {
                if (
                    jwk.crv !in setOf(
                        Curve.P_256.name,
                        Curve.P_384.name,
                        Curve.P_521.name
                    )
                ) {
                    throw OpenID4VPExceptions.JweEncryptionFailure(
                        "Unsupported EC curve for ECDH-ES: ${jwk.crv}. Only P-256, P-384, P-521 are supported.",
                        className
                    )
                }

                ECDHEncrypter(getPublicEcKey(jwk))
            }

            else -> throw OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm(className)
        }
    }

    private fun getPublicOctetKey(jwk: Jwk): OctetKeyPair {
        val builder = OctetKeyPair.Builder(Curve(jwk.crv), Base64URL.from(jwk.x))
            .keyID(jwk.kid)
            .algorithm(Algorithm.parse(jwk.alg))

        jwk.use?.let { builder.keyUse(KeyUse(it)) }

        return builder
            .build()
            .toPublicJWK()
    }

    private fun getPublicEcKey(jwk: Jwk): ECKey {
        val y = jwk.y ?: throw OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm(className)
        val builder = ECKey.Builder(
            Curve(jwk.crv),
            Base64URL.from(jwk.x),
            Base64URL.from(y)
        )
            .keyID(jwk.kid)
            .algorithm(Algorithm.parse(jwk.alg))

        jwk.use?.let { builder.keyUse(KeyUse(it)) }

        return builder.build().toPublicJWK()
    }
}
