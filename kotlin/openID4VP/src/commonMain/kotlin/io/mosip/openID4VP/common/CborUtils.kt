package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.DoublePrecisionFloat
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 *  #6.24 (bstr .cbor data)
 *
 *  #6.24 -> tag
 *  bstr -> bytestring .cbor => bytestring is an cbor encoded data
 *
 *  #6.24 (encoded cbor data)
 *  24 ( << data>>)
 */

fun tagEncodedCbor(input: DataItem): DataItem {
    val tagValue = 24L
    val taggedEncodedCborData = CborBuilder().add(encodeCbor(input)).build()[0]
    taggedEncodedCborData.setTag(tagValue)
    return taggedEncodedCborData

}

fun encodeCbor(input: DataItem): ByteArray {
    val outputStream = ByteArrayOutputStream()
    CborEncoder(outputStream).encode(input)
    val byteArray = outputStream.toByteArray()
    outputStream.flush()
    return byteArray
}

fun decodeCbor(input: ByteArray): DataItem {
    val byteArrayInputStream = ByteArrayInputStream(input)
    val decodedData = CborDecoder(byteArrayInputStream).decode()
     byteArrayInputStream.close()
    return decodedData[0]
}

fun cborArrayOf(vararg items: Any?): DataItem {
    val builder = CborBuilder().addArray()
    items.forEach { item ->
        when (item) {
            is String -> builder.add(item)
            is ByteArray -> builder.add(item)
            is Int -> builder.add(item.toLong())
            is Long -> builder.add(item)
            is Double -> builder.add(item)
            is DataItem -> builder.add(item)
            null -> builder.add(null as DataItem?)
            else -> throw IllegalArgumentException("Unsupported type: ${item::class}")  //TODO: revisit the error handling
        }
    }
    return builder.end().build()[0]
}

fun cborMapOf(vararg pairs: Pair<Any?, Any?>): DataItem {
    val builder = CborBuilder().addMap()
    pairs.forEach { (key, value) ->
        val keyItem = toDataItem(key, isKey = true)
        val valueItem = toDataItem(value)
        builder.put(keyItem, valueItem)
    }
    return builder.end().build()[0]
}

private fun toDataItem(value: Any?, isKey: Boolean = false): DataItem? {
    return when (value) {
        is String -> UnicodeString(value)
        is ByteArray -> ByteString(value)
        is Int -> if (value >= 0) UnsignedInteger(value.toLong()) else NegativeInteger(value.toLong())
        is Long -> if (value >= 0) UnsignedInteger(value) else NegativeInteger(value)
        is Double -> DoublePrecisionFloat(value)
        is DataItem -> value
        null -> if (isKey) throw IllegalArgumentException("Key cannot be null") else null
        else -> throw IllegalArgumentException("Unsupported ${if (isKey) "key" else "value"} type: ${value.javaClass}")
    }
}

fun createHashedDataItem(vararg items: Any?): ByteString {
    val dataItem = cborArrayOf(*items)
    return ByteString(generateHash(dataItem))
}

fun generateHash(input: DataItem): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    val encodedCbor = encodeCbor(input)
    val hashBytes = digest.digest(encodedCbor)
    return hashBytes
}

fun getDecodedMdocCredential(mdocCredential: String): Map {
    val base64DecodedMdocCredential = decodeFromBase64Url(mdocCredential)
    return decodeCbor(base64DecodedMdocCredential) as Map
}

fun mapSigningAlgorithmToProtectedAlg(algorithm: String): Long {
    return when (algorithm) {
        "ES256" -> -7   // ECDSA w/ SHA-256
        "ES384" -> -35  // ECDSA w/ SHA-384
        "ES512" -> -36  // ECDSA w/ SHA-512
        "EdDSA" -> -8  // EdDSA
        "PS256" -> -37  // RSASSA-PSS w/ SHA-256
        "PS384" -> -38  // RSASSA-PSS w/ SHA-384
        "PS512" -> -39  // RSASSA-PSS w/ SHA-512
        else -> throw IllegalArgumentException("Unsupported signing algorithm: $algorithm")
    }
}

// RFC 7638 JWK Thumbprint — SHA-256 hash of the canonical JSON representation
// TODO: Nimbus has ThumbprintUtils.compute(JWK) / jwk.computeThumbprint().decode() which does this natively,
//  but it requires a Nimbus JWK instance. Replace once Jwk -> Nimbus migration ticket is done.
fun jwkThumbprintBytes(jwk: Jwk): ByteArray {
    val canonicalJson = when (jwk.kty.uppercase()) {
        "EC" -> """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}"""
        "OKP" -> """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}"""
        // RSA requires 'e' and 'n' fields which are not in the current Jwk model
        "RSA" -> throw IllegalArgumentException("RSA key type not supported in current Jwk model")
        else -> throw IllegalArgumentException("Unsupported key type for JWK thumbprint: ${jwk.kty}")
    }
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(canonicalJson.toByteArray(Charsets.UTF_8))
}

fun toJWKThumbprintBstr(jwk: Jwk): ByteString {
    return ByteString(jwkThumbprintBytes(jwk))
}
