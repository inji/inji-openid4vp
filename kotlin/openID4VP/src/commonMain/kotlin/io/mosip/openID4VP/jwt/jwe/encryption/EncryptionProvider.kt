package io.mosip.openID4VP.jwt.jwe.encryption

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = EncryptionProvider::class.simpleName!!
object EncryptionProvider {

    fun getEncrypter(jwk: Jwk): JWEEncrypter =
        when (jwk.kty) {
            KeyType.OKP.value -> X25519Encrypter(getPublicOctetKey(jwk))
            else -> throw OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm(className)
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
}
