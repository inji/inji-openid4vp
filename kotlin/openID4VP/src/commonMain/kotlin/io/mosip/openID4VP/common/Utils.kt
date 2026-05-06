package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

private const val URL_PATTERN =
    "^https://(?:[\\w-]+\\.)+[\\w-]+(?:/[\\w\\-.~!$&'()*+,;=:@%]+)*/?(?:\\?[^#\\s]*)?(?:#.*)?$"

fun isValidUrl(url: String): Boolean {
    return url.matches(URL_PATTERN.toRegex())
}

fun convertJsonToMap(jsonString: String): MutableMap<String, Any> {
    return getObjectMapper().readValue(
        jsonString,
        object : TypeReference<MutableMap<String, Any>>() {})
}

fun isJWS(input: String): Boolean {
    return input.split(".").size == 3
}

fun determineHttpMethod(method: String): HttpMethod {
    return when (method.lowercase()) {
        "get" -> HttpMethod.GET
        "post" -> HttpMethod.POST
        else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
    }
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

fun generateNonce(minEntropy: Int = 16): String {
    val secureRandom = SecureRandom()
    val bytes = ByteArray(minEntropy)
    secureRandom.nextBytes(bytes)
    return encodeToBase64Url(bytes)
}

fun validate(
    key: String,
    value: String?,
    className: String,
    fieldType: String = "String"
) {
    if (value == null || value == "null" || value.isEmpty()) {
        throw if (value == null) {
            OpenID4VPExceptions.MissingInput(listOf(key), "", className)
        } else {
            OpenID4VPExceptions.InvalidInput(listOf(key), fieldType, className)
        }
    }
}

inline fun <reified T> encodeToJsonString(data: T, fieldName: String, className: String): String {
    try {
        val objectMapper =
            jacksonObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)
        return objectMapper.writeValueAsString(data)
    } catch (exception: Exception) {
        throw OpenID4VPExceptions.JsonEncodingFailed(
            listOf(fieldName),
            exception.message.toString(),
            className
        )
    }
}

fun ByteArray.toHex(): String {
    return this.joinToString("") { "%02x".format(it) }
}

fun getObjectMapper(): ObjectMapper {
    return JacksonObjectMapper.instance
}

fun hashData(data: String, algorithm: String = "SHA-256"): String {
    val digest = MessageDigest.getInstance(algorithm)
    val hash = digest.digest(data.toByteArray(Charsets.UTF_8))
    return encodeToBase64Url(hash)
}

fun createNestedPath(
    inputDescriptorId: String,
    nestedPath: String?,
    format: FormatType
): PathNested? {
    if (nestedPath == null) return null
    return PathNested(
        id = inputDescriptorId,
        format = format.value,
        path = nestedPath
    )
}

fun createDescriptorMapPath(vpIndex: Int) = "$[$vpIndex]"

internal fun resolveJwksFromUri(jwksUri: String, className: String): Jwks {
    return try {
        val response: NetworkResponse =
            NetworkManagerClient.sendHTTPRequest(jwksUri, HttpMethod.GET)

        if (!response.isOk()) {
            throw InvalidData(
                "Error while fetching jwks information, status code: ${response.statusCode} with body: ${response.body}",
                className
            )
        }

        getObjectMapper().readValue(response.body, Jwks::class.java)
    } catch (e: Exception) {
        throw InvalidData(
            "Public key extraction failed - Unable to fetch/parse jwks from $jwksUri due to ${e.message}",
            className,
            OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
        )
    }
}

internal fun constructSigningResults(
    unsignedVPTokenResults: Map<FormatType, Pair<Any?, List<UnsignedVPToken>>>,
    signingResults: List<VPTokenSigningResult>,
    className: String
): Map<FormatType, List<VPTokenSigningResult>> {

    val iterator = signingResults.iterator()
    val reconstructed = mutableMapOf<FormatType, List<VPTokenSigningResult>>()

    unsignedVPTokenResults.keys
        .sortedBy { it.value }
        .forEach { format ->
            val pair = unsignedVPTokenResults[format]!!
            val unsignedTokens = pair.second
            val count = unsignedTokens.size

            val formatResults = mutableListOf<VPTokenSigningResult>()
            repeat(count) {
                if (!iterator.hasNext()) {
                    throw InvalidData(
                        if (format == FormatType.MSO_MDOC) {
                            "Missing mdoc signature"
                        } else {
                            "Missing signing result for format $format"
                        },
                        className
                    )
                }
                formatResults.add(iterator.next())
            }
            reconstructed[format] = formatResults
        }

    if (iterator.hasNext()) {
        throw InvalidData("Extra signing results provided", className)
    }

    return reconstructed
}

fun resolveLdpHolderKey(credential: Any, className: String): String {

    val vcMap = credential as? Map<*, *>
        ?: throw InvalidData("Invalid LDP credential structure", className)

    val credentialSubject = vcMap["credentialSubject"] as? Map<*, *>
        ?: throw InvalidData("credentialSubject missing", className)

    return credentialSubject["id"] as? String
        ?: throw InvalidData("credentialSubject.id missing", className)
}

fun resolveMdocKeyAndAlg(mdocCredential: String, className: String): Pair<String, String> =
    extractMdocKeyReferenceAndAlg(mdocCredential, className)

private fun extractMdocKeyReferenceAndAlg(
    mdocCredential: String,
    className: String
): Pair<String, String> {
    val decoded = getDecodedMdocCredential(mdocCredential)

    val issuerSigned = decoded[UnicodeString("issuerSigned")] as? co.nstant.`in`.cbor.model.Map
        ?: throw InvalidData("issuerSigned missing", className)

    val issuerAuthArray =
        issuerSigned[UnicodeString("issuerAuth")] as? co.nstant.`in`.cbor.model.Array
            ?: throw InvalidData("issuerAuth not COSE_Sign1", className)

    val payloadBytes = issuerAuthArray.dataItems[2] as? ByteString
        ?: throw InvalidData("issuerAuth payload missing", className)

    // Decode payload
    val firstDecoded = CborDecoder(ByteArrayInputStream(payloadBytes.bytes)).decode().first()

    // Handle Tag 24 (encoded CBOR)
    val msoDataItem = if (firstDecoded.tag?.value == 24L) {
        val innerBytes = (firstDecoded as? ByteString)?.bytes
            ?: throw InvalidData("Tag 24 inner not bstr", className)

        CborDecoder(ByteArrayInputStream(innerBytes)).decode().first()
    } else {
        firstDecoded
    }

    val mso = msoDataItem as? co.nstant.`in`.cbor.model.Map
        ?: throw InvalidData("MSO not map after unwrap", className)

    val deviceKeyInfo = mso[UnicodeString("deviceKeyInfo")] as? co.nstant.`in`.cbor.model.Map
        ?: throw InvalidData("deviceKeyInfo missing", className)

    val deviceKey = deviceKeyInfo[UnicodeString("deviceKey")] as? co.nstant.`in`.cbor.model.Map
        ?: throw InvalidData("deviceKey missing", className)

    val keyBytes = encodeCbor(deviceKey)
    val keyRef = encodeToBase64Url(keyBytes)

    val algKey = UnsignedInteger(3)
    val algItem = deviceKey[algKey]

    val alg = if (algItem != null) {
        val coseAlg = when (algItem) {
            is NegativeInteger -> algItem.value.toInt()
            is UnsignedInteger -> algItem.value.toInt()
            else -> throw InvalidData("Invalid alg type", className)
        }

        when (coseAlg) {
            -7 -> "ES256"
            -8 -> "EdDSA"
            else -> throw InvalidData(
                "Unsupported COSE alg $coseAlg",
                className
            )
        }
    } else {
        val crvKey = NegativeInteger(-1)
        val crvItem = deviceKey[crvKey]
            ?: throw InvalidData("crv missing for alg inference", className)

        val crv = when (crvItem) {
            is UnsignedInteger -> crvItem.value.toInt()
            else -> throw InvalidData("Invalid crv type", className)
        }

        when (crv) {
            1 -> "ES256"   // P-256
            6 -> "EdDSA"   // Ed25519
            else -> throw InvalidData("Unsupported crv $crv", className)
        }
    }

    return keyRef to alg
}

fun resolveSdJwtKeyAndAlg(sdJwtCredential: String, className: String): Pair<String, String> {

    val sdJwt = sdJwtCredential.split("~")[0]
    val payload = JWSHandler.extractDataJsonFromJws(sdJwt, JWSHandler.JwsPart.PAYLOAD)

    val cnf = payload["cnf"] as? Map<*, *>
        ?: throw InvalidData("cnf missing in SD-JWT", className)

    val kid = cnf["kid"] as? String
        ?: throw InvalidData("cnf.kid missing", className)

    val publicKey = DidPublicKeyResolver().resolve(kid.trimEnd('='), null)

    val alg = when (publicKey.algorithm) {
        "Ed25519" -> "EdDSA"
        "EC" -> "ES256"
        "RSA" -> "RS256"
        else -> throw InvalidData("Unsupported key algorithm ${publicKey.algorithm}", className)
    }

    return kid to alg
}

private val BASE58_BTCALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

fun encodeToMultibaseBase58btc(base64Url: String): String {
    val padded = base64Url
        .replace('-', '+')
        .replace('_', '/')
        .let { it + "=".repeat((4 - it.length % 4) % 4) }
    val bytes = Base64.getDecoder().decode(padded)
    val leadingZeros = bytes.takeWhile { it == 0.toByte() }.count()
    var value = BigInteger(1, bytes)
    val base = BigInteger.valueOf(58)
    val sb = StringBuilder()
    while (value > BigInteger.ZERO) {
        val (quotient, remainder) = value.divideAndRemainder(base)
        sb.append(BASE58_BTCALPHABET[remainder.toInt()])
        value = quotient
    }
    repeat(leadingZeros) { sb.append(BASE58_BTCALPHABET[0]) }
    return "z" + sb.reverse().toString()
}
