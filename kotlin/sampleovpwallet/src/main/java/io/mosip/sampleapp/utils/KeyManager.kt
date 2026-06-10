package io.mosip.sampleapp.utils;

import com.google.gson.JsonObject
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Date
import java.util.UUID

enum class KeyType {
    RSA, ES256, Ed25519
}

data class SignedVPJWT(
    val jws: String,
    val proofValue: String? = null,
    val signatureAlgorithm: String
)

object VPTokenSigner {

    private fun signVPTokenWithRSAorEC(
        keyType: KeyType,
        vpPayload: String,
        keyPair: KeyPair,
    ): SignedVPJWT {
        val jwk: JWK
        val signer: JWSSigner
        val alg: JWSAlgorithm

        when (keyType) {
            KeyType.RSA -> {
                val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
                    .privateKey(keyPair.private as RSAPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build()
                jwk = rsaKey
                signer = RSASSASigner(rsaKey)
                alg = JWSAlgorithm.RS256
            }
            KeyType.ES256 -> {
                val ecKey = ECKey.Builder(Curve.P_256, keyPair.public as ECPublicKey)
                    .privateKey(keyPair.private as ECPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build()
                jwk = ecKey
                signer = ECDSASigner(ecKey)
                alg = JWSAlgorithm.ES256
            }

            else -> throw IllegalArgumentException("Unsupported key type: $keyType")
        }

        val claimsSet = JWTClaimsSet.Builder()
            .issuer("did:jwk")
            .issueTime(Date())
            .claim("vp", vpPayload)
            .build()

        val signedJWT = SignedJWT(
            JWSHeader.Builder(alg).keyID(jwk.keyID).type(JOSEObjectType.JWT).build(),
            claimsSet
        )
        signedJWT.sign(signer)

        return SignedVPJWT(signedJWT.serialize(), jwk.toPublicJWK().toJSONString(), alg.name)
    }

    fun signVpToken(
        keyType: KeyType,
        dataToSign: ByteArray,
        keyPair: Any
    ) = when (keyType) {
        KeyType.RSA, KeyType.ES256 -> {
            signVPTokenWithRSAorEC(keyType, String(dataToSign, Charsets.UTF_8), keyPair as KeyPair)
        }

        KeyType.Ed25519 -> {
            DetachedJwtKeyManager.signDetachedVpJWT(dataToSign, keyPair as OctetKeyPair)
        }
    }

    fun signDeviceAuthentication(
        keyPair: KeyPair,
        keyType: KeyType,
        deviceAuthBytes: ByteArray
    ): SignedVPJWT {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build()
        val payload = Payload(deviceAuthBytes)
        val jwsObject = JWSObject(header, payload)

        val signer = when (keyType) {
            KeyType.ES256 -> ECDSASigner(keyPair.private as ECPrivateKey)
            KeyType.RSA -> RSASSASigner(keyPair.private)
            else -> throw Exception("Unsupported key type for signing device authentication")
        }
        jwsObject.sign(signer)

        return SignedVPJWT(
            jws = jwsObject.serialize(),
            signatureAlgorithm = jwsObject.header.algorithm.name
        )
    }
}



object SampleKeyGenerator {

    const val SIGNATURE_SUITE = "JsonWebSignature2020"

    fun generateKeyPair(keyType: KeyType): Any {
        return when (keyType) {
            KeyType.RSA -> {
                val keyGen = KeyPairGenerator.getInstance("RSA")
                keyGen.initialize(2048)
                keyGen.generateKeyPair()
            }
            KeyType.ES256 -> {
                val keyGen = KeyPairGenerator.getInstance("EC")
                keyGen.initialize(Curve.P_256.toECParameterSpec())
                keyGen.generateKeyPair()
            }
            KeyType.Ed25519 -> {
                DetachedJwtKeyManager.generateEd25519JWK()
            }
        }
    }

}

object MdocKeyManager {
    fun getIssuerAuthenticationAlgorithmForMdocVC(proofType: Int): String {
        return when (proofType) {
            -7 -> "ES256"
            else -> ""
        }
    }

    fun getMdocAuthenticationAlgorithm(issuerAuth: JsonObject): String {
        val deviceKey = issuerAuth.getAsJsonObject("deviceKeyInfo")?.getAsJsonObject("deviceKey") ?: return ""

        val keyType = deviceKey["1"]?.asInt
        val curve = deviceKey["-1"]?.asInt

        return if (keyType == ProtectedAlgorithm.EC2 && curve == ProtectedCurve.P256) "ES256" else ""
    }
    private object ProtectedAlgorithm {
        const val EC2 = 2
    }

    private object ProtectedCurve {
        const val P256 = 1
    }
}
