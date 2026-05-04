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
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenV2
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResultV2
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.SecureRandom

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

internal fun flattenUnsignedVPTokens(
    unsignedVPTokenResults: Map<FormatType, Pair<VPTokenSigningPayload?, UnsignedVPToken>>,
    formatMappings: Map<FormatType, List<CredentialInputDescriptorMapping>>,
    signatureSuite: String?,
    holderId: String?,
    className: String
): List<UnsignedVPTokenV2> {

    val result = mutableListOf<UnsignedVPTokenV2>()

    unsignedVPTokenResults.keys.sortedBy { it.value }.forEach { format ->
        val pair = unsignedVPTokenResults[format]
        val unsignedToken = pair!!.second
        val mappings = formatMappings[format]
            ?: throw InvalidData("Missing mapping for $format", className)

        when (format) {
            FormatType.LDP_VC -> result += flattenLdp(
                unsignedToken,
                mappings,
                signatureSuite,
                holderId,
                className
            )

            FormatType.MSO_MDOC -> result += flattenMdoc(unsignedToken, mappings, className)
            FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> result += flattenSdJwt(
                unsignedToken,
                mappings,
                format,
                className
            )
        }
    }

    return result
}

internal fun constructSigningResults(
    unsignedVPTokenResults: Map<FormatType, Pair<VPTokenSigningPayload?, UnsignedVPToken>>,
    formatMappings: Map<FormatType, List<CredentialInputDescriptorMapping>>,
    signingResults: List<VPTokenSigningResultV2>,
    signatureSuite: String,
    className: String
): Map<FormatType, VPTokenSigningResult> {

    val iterator = signingResults.iterator()

    val reconstructed = mutableMapOf<FormatType, VPTokenSigningResult>()

    unsignedVPTokenResults.keys
        .sortedBy { it.value }
        .forEach { format ->

            val pair = unsignedVPTokenResults[format]!!
            val unsignedToken = pair.second
            val mappings = formatMappings[format]!!

            val result = when (format) {
                FormatType.LDP_VC ->
                    constructLdp(iterator, signatureSuite, className)

                FormatType.MSO_MDOC ->
                    constructMdoc(unsignedToken, mappings, iterator, className)

                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT ->
                    constructSdJwt(unsignedToken, iterator, className)
            }

            reconstructed[format] = result
        }


    if (iterator.hasNext()) {
        throw InvalidData("Extra signing results provided", className)
    }

    return reconstructed
}

internal fun flattenLdp(
    unsignedToken: UnsignedVPToken,
    mappings: List<CredentialInputDescriptorMapping>,
    signatureSuite: String?,
    holderId: String?,
    className: String
): List<UnsignedVPTokenV2> {

    val ldp = unsignedToken as UnsignedLdpVPToken

    val credential = mappings.firstOrNull()?.credential
        ?: throw InvalidData("No LDP credential found", className)

    val holderKeyRef = holderId ?: resolveLdpHolderKey(
        credential,
        className = className
    )

    return listOf(
        UnsignedVPTokenV2(
            format = FormatType.LDP_VC,
            holderKeyReference = holderKeyRef,
            signatureAlgorithm = signatureSuite
                ?: throw InvalidData("signatureSuite required for LDP", className),
            dataToSign = ldp.dataToSign
        )
    )
}

internal fun flattenMdoc(
    unsignedToken: UnsignedVPToken,
    mappings: List<CredentialInputDescriptorMapping>,
    className: String
): List<UnsignedVPTokenV2> {

    val mdoc = unsignedToken as UnsignedMdocVPToken

    return mdoc.docTypeToDeviceAuthenticationBytes.keys
        .sorted()
        .map { docType ->
            val bytesToSign = mdoc.docTypeToDeviceAuthenticationBytes[docType]!!
            val mapping = mappings.firstOrNull { it.identifier == docType }
                ?: throw InvalidData("No mapping for docType $docType", className)

            val (keyRef, alg) = resolveMdocKeyAndAlg(mapping.credential as String, className)

            UnsignedVPTokenV2(
                format = FormatType.MSO_MDOC,
                holderKeyReference = keyRef,
                signatureAlgorithm = alg,
                dataToSign = bytesToSign
            )
        }
}

internal fun flattenSdJwt(
    unsignedToken: UnsignedVPToken,
    mappings: List<CredentialInputDescriptorMapping>,
    format: FormatType,
    className: String
): List<UnsignedVPTokenV2> {

    val sdjwt = unsignedToken as UnsignedSdJwtVPToken

    val uuidToMapping = mappings.mapNotNull { m -> m.identifier?.let { it to m } }.toMap()

    return sdjwt.uuidToUnsignedKBT.keys
        .sorted()
        .map { uuid ->
            val unsignedKbJwt = sdjwt.uuidToUnsignedKBT[uuid]!!
            val mapping = uuidToMapping[uuid]
                ?: throw InvalidData("No SD-JWT mapping for uuid $uuid", className)

            val (kid, alg) = resolveSdJwtKeyAndAlg(mapping.credential as String, className)

            UnsignedVPTokenV2(format, kid, alg, unsignedKbJwt)
        }
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

fun constructLdp(
    iterator: Iterator<VPTokenSigningResultV2>,
    signatureSuite: String,
    className: String
): VPTokenSigningResult {

    val signed = iterator.nextOrError("Missing LDP signature", className)

    return if (
        signatureSuite == SignatureSuiteAlgorithm.JsonWebSignature2020.value ||
        signatureSuite == SignatureSuiteAlgorithm.RSASignature2018.value ||
        signatureSuite == SignatureSuiteAlgorithm.Ed25519Signature2018.value
    ) {
        LdpVPTokenSigningResult(
            jws = signed.signedData,
            signatureAlgorithm = signatureSuite
        )
    } else {
        LdpVPTokenSigningResult(
            proofValue = signed.signedData,
            jws = null,
            signatureAlgorithm = signatureSuite
        )
    }
}

internal fun constructMdoc(
    unsignedToken: UnsignedVPToken,
    mappings: List<CredentialInputDescriptorMapping>,
    iterator: Iterator<VPTokenSigningResultV2>,
    className: String
): VPTokenSigningResult {

    val unsignedMdoc = unsignedToken as UnsignedMdocVPToken
    val deviceAuthMap = mutableMapOf<String, DeviceAuthentication>()

    unsignedMdoc.docTypeToDeviceAuthenticationBytes.keys
        .sorted()
        .forEach { docType ->
            val signed =
                iterator.nextOrError("Missing mdoc signature for docType $docType", className)

            val mapping = mappings.first { it.identifier == docType }
            val (_, alg) = resolveMdocKeyAndAlg(mapping.credential as String, className)

            deviceAuthMap[docType] = DeviceAuthentication(signed.signedData, alg)
        }

    return MdocVPTokenSigningResult(deviceAuthMap)
}

fun constructSdJwt(
    unsignedToken: UnsignedVPToken,
    iterator: Iterator<VPTokenSigningResultV2>,
    className: String
): VPTokenSigningResult {

    val unsignedSd = unsignedToken as UnsignedSdJwtVPToken

    val uuidToSig = unsignedSd.uuidToUnsignedKBT.keys
        .sorted()
        .associateWith { uuid ->
            iterator.nextOrError(
                "Missing SD-JWT signature for uuid $uuid",
                className
            ).signedData
        }


    return SdJwtVPTokenSigningResult(uuidToSig)
}

private fun <T> Iterator<T>.nextOrError(msg: String, className: String): T =
    if (hasNext()) next()
    else throw InvalidData(msg, className)

