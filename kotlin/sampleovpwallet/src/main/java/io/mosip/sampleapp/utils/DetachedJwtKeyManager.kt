package io.mosip.sampleapp.utils

import com.google.crypto.tink.subtle.Base64
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import java.nio.charset.StandardCharsets


object DetachedJwtKeyManager {

    fun generateHolderId(jwk: OctetKeyPair): String {
        val publicJwkJson = jwk.toPublicJWK().toJSONString()
        val encoded = Base64URL.encode(publicJwkJson.toByteArray(StandardCharsets.UTF_8)).toString()
        return "did:jwk:$encoded#0"
    }

    fun generateEd25519JWK(): OctetKeyPair {
        return OctetKeyPairGenerator(Curve.Ed25519)
            .keyIDFromThumbprint(true)
            .generate()
    }

    private fun constructDetachedJWS(jwk: OctetKeyPair, payloadMap: String): String {
        val header = JWSHeader.Builder(JWSAlgorithm.EdDSA)
            .base64URLEncodePayload(false)
            .criticalParams(setOf("b64"))
            .build()
        val headerB64 = header.toBase64URL().toString()
        val encodedHeader: ByteArray = headerB64.toByteArray(Charsets.UTF_8)

        val payloadBytes = Base64.urlSafeDecode(payloadMap)
        val signingInput = encodedHeader + byteArrayOf(46) + payloadBytes

        val signer = Ed25519Signer(jwk)
        val signatureB64Url = signer.sign(header, signingInput)

        return "$headerB64..${signatureB64Url}"
    }



    fun signDetachedVpJWT(payloadMap: String, keyPair: OctetKeyPair): SignedVPJWT {
        val proof = constructDetachedJWS(keyPair, payloadMap)
        return SignedVPJWT(
            jws = proof,
            signatureAlgorithm = "EdDSA"
        )
    }

    fun signDetachedVpJWT(dataToSign: ByteArray, keyPair: OctetKeyPair): SignedVPJWT {
        val header = JWSHeader.Builder(JWSAlgorithm.EdDSA)
            .base64URLEncodePayload(false)
            .criticalParams(setOf("b64"))
            .build()
        val headerB64 = header.toBase64URL().toString()
        val signer = Ed25519Signer(keyPair)
        val signatureB64Url = signer.sign(header, dataToSign)
        return SignedVPJWT(
            jws = "$headerB64..$signatureB64Url",
            signatureAlgorithm = "EdDSA"
        )
    }



}
