package io.mosip.openID4VP.dcql.evaluator

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.DoublePrecisionFloat
import co.nstant.`in`.cbor.model.HalfPrecisionFloat
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.SinglePrecisionFloat
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.common.JsonLDProcessor
import io.mosip.openID4VP.common.MdocCredentialUtils.getMdocDocType
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.wallet.Credential
import jakarta.json.JsonString
import java.security.MessageDigest
import kotlin.collections.get
import kotlin.collections.iterator

private const val CLASS_NAME = "DCQLUtils"

@Suppress("UNCHECKED_CAST")
internal fun expandCredentialTag(credential: Credential): TaggedCredential {
    return when (credential.format) {
        FormatType.LDP_VC -> {
            val credentialData = credential.data as? Map<String, Any>
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Credential data is not in the expected format", CLASS_NAME
                )
            val credentialSubject = credentialData["credentialSubject"] as? Map<String, Any>
            val credentialSubjectId = credentialSubject?.get("id") as? String
            val types = expandAndExtractTypes(credentialData)
            W3cTaggedCredential(
                credentialFormat = credential.format,
                hasCryptographicHolderBinding = credentialSubjectId != null,
                types = types
            )
        }

        FormatType.MSO_MDOC -> {
            val mdocCredential = credential.data as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "MDOC credential is not a String", CLASS_NAME
                )
            val docType = getMdocDocType(mdocCredential, CLASS_NAME)
            MdocTaggedCredential(
                hasCryptographicHolderBinding = true,
                doctype = docType
            )
        }

        FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
            val sdJwtCredential = credential.data as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "SD-JWT credential is not a String", CLASS_NAME
                )
            val payload = extractSdJwtPayloadMap(sdJwtCredential)
            SdJwtTaggedCredential(
                credentialFormat = credential.format,
                hasCryptographicHolderBinding = payload.containsKey("cnf"),
                vct = payload["vct"] as? String ?: ""
            )
        }
    }
}

@Suppress("UNCHECKED_CAST")
internal fun convertToProcessedCredentials(
    filteredWalletCredentialIds: List<String>,
    credentialIdToCredential: Map<String, Credential>
): Map<String, ProcessedCredential> {
    val processedCredentials = mutableMapOf<String, ProcessedCredential>()

    for (credentialId in filteredWalletCredentialIds) {
        val credential = credentialIdToCredential[credentialId] ?: continue

        when (credential.format) {
            FormatType.LDP_VC -> {
                val credentialData = credential.data as? Map<String, Any>
                    ?: throw OpenID4VPExceptions.InvalidData(
                        "Credential data is not in the expected format", CLASS_NAME
                    )
                processedCredentials[credentialId] = W3cProcessedCredential(
                    credentialId = credential.credentialId,
                    credentialFormat = credential.format,
                    claims = credentialData
                )
            }

            FormatType.MSO_MDOC -> {
                val mdocCredential = credential.data as? String
                    ?: throw OpenID4VPExceptions.InvalidData(
                        "MDOC credential is not a String", CLASS_NAME
                    )
                val decodedMdoc = decodeCbor(decodeFromBase64Url(mdocCredential)) as co.nstant.`in`.cbor.model.Map
                val namespaces = extractMdocNamespaces(decodedMdoc)
                processedCredentials[credentialId] = MdocProcessedCredential(
                    credentialId = credential.credentialId,
                    namespaces = namespaces
                )
            }

            FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
                val sdJwtCredential = credential.data as? String
                    ?: throw OpenID4VPExceptions.InvalidData(
                        "SD-JWT credential is not a String", CLASS_NAME
                    )
                val fullyResolvedClaims = extractSdJwtResolvedClaims(sdJwtCredential)
                processedCredentials[credentialId] = SdJwtProcessedCredential(
                    credentialId = credential.credentialId,
                    credentialFormat = credential.format,
                    claims = fullyResolvedClaims
                )
            }
        }
    }

    return processedCredentials
}

@Suppress("UNCHECKED_CAST")
internal fun resolveClaimsPathPointer(path: List<Any?>, claims: Any?): Any? {
    var selectedElement: Any? = claims

    for ((i, pathPointer) in path.withIndex()) {
        when {
            pathPointer is String -> {
                when {
                    selectedElement is Map<*, *> -> {
                        selectedElement = selectedElement[pathPointer]
                    }
                    i > 0 && isNullPathPointer(path[i - 1]) -> {
                        val selectedArray = selectedElement as? List<Map<String, Any>>
                            ?: throw OpenID4VPExceptions.InvalidData(
                                "currently selected element(s) is not an object", CLASS_NAME
                            )
                        val selectedValues = selectedArray.mapNotNull { it[pathPointer] }
                        selectedElement = selectedValues.ifEmpty { null }
                    }
                    else -> throw OpenID4VPExceptions.InvalidData(
                        "currently selected element(s) is not an object", CLASS_NAME
                    )
                }
            }
            pathPointer is Number -> {
                val index = pathPointer.toInt()
                val selectedArray = selectedElement as? List<*>
                    ?: throw OpenID4VPExceptions.InvalidData(
                        "currently selected element(s) is not an array", CLASS_NAME
                    )
                selectedElement = if (index < 0 || index >= selectedArray.size) null
                else selectedArray[index]
            }
            isNullPathPointer(pathPointer) -> {
                if (selectedElement !is List<*>) {
                    throw OpenID4VPExceptions.InvalidData(
                        "currently selected element(s) is not an array", CLASS_NAME
                    )
                }
            }
            else -> throw OpenID4VPExceptions.InvalidData(
                "Unexpected path pointer component", CLASS_NAME
            )
        }
    }
    return selectedElement
}

private fun isNullPathPointer(value: Any?): Boolean {
    return value == null
}

// SD-JWT utilities

private fun expandAndExtractTypes(credentialData: Map<String, Any>): List<String> {
    return try {
        val expanded = JsonLDProcessor.expand(credentialData)
        if (expanded.isEmpty()) return emptyList()
        val firstObj = expanded.getJsonObject(0) ?: return emptyList()
        val typeArray = firstObj.getJsonArray("@type") ?: return emptyList()
        typeArray.mapNotNull { (it as? JsonString)?.string }
    } catch (exception: Exception) {
        OpenID4VPExceptions.error("Error during JSON-LD expansion: ${exception.message}", CLASS_NAME)
        emptyList()
    }
}

internal fun extractSdJwtPayloadMap(sdJwtCredential: String): Map<String, Any> {
    val parts = sdJwtCredential.split("~")
    val jwtPart = parts.firstOrNull()?.takeIf { it.isNotEmpty() }
        ?: throw OpenID4VPExceptions.InvalidData(
            "SD-JWT credential is malformed or empty", CLASS_NAME
        )

    val payloadPart = jwtPart.split(".").getOrNull(1)
        ?: throw OpenID4VPExceptions.InvalidData(
            "SD-JWT credential JWT part is malformed", CLASS_NAME
        )

    val payloadJson = String(decodeFromBase64Url(payloadPart))
    val objectMapper = getObjectMapper()
    @Suppress("UNCHECKED_CAST")
    return objectMapper.readValue(payloadJson, Map::class.java) as Map<String, Any>
}

@Suppress("UNCHECKED_CAST")
internal fun extractSdJwtResolvedClaims(sdJwtCredential: String): Map<String, Any> {
    val parts = sdJwtCredential.split("~")
    val jwtPart = parts.first()
    val payloadPart = jwtPart.split(".").getOrNull(1)
        ?: throw OpenID4VPExceptions.InvalidData(
            "SD-JWT credential JWT part is malformed", CLASS_NAME
        )

    val payloadJson = String(decodeFromBase64Url(payloadPart))
    val objectMapper = getObjectMapper()
    val payload = objectMapper.readValue(payloadJson, Map::class.java) as Map<String, Any>

    // Build disclosure map: SHA-256(disclosure) -> (claimName, claimValue)
    val disclosureMap = mutableMapOf<String, Pair<String, Any>>()
    val disclosures = parts.drop(1).filter { it.isNotEmpty() }
    for (disclosure in disclosures) {
        try {
            val decoded = decodeFromBase64Url(disclosure)
            val decodedArray = objectMapper.readValue(decoded, List::class.java) as? List<Any>
            if (decodedArray != null && decodedArray.size >= 3) {
                val claimName = decodedArray[1] as? String ?: continue
                val claimValue = decodedArray[2]
                val digest = sha256Base64Url(disclosure.toByteArray(Charsets.UTF_8))
                disclosureMap[digest] = Pair(claimName, claimValue)
            }
        } catch (_: Exception) {
            continue
        }
    }

    return resolveSDJWTClaims(payload, disclosureMap)
}

@Suppress("UNCHECKED_CAST")
private fun resolveSDJWTClaims(
    obj: Map<String, Any>,
    disclosureMap: Map<String, Pair<String, Any>>
): Map<String, Any> {
    val result = mutableMapOf<String, Any>()

    val sdHashes = obj["_sd"] as? List<String>
    sdHashes?.forEach { hash ->
        disclosureMap[hash]?.let { (claimName, claimValue) ->
            result[claimName] = when (claimValue) {
                is Map<*, *> -> resolveSDJWTClaims(claimValue as Map<String, Any>, disclosureMap)
                else -> claimValue
            }
        }
    }

    for ((key, value) in obj) {
        if (key == "_sd" || key == "_sd_alg") continue
        result[key] = when (value) {
            is Map<*, *> -> resolveSDJWTClaims(value as Map<String, Any>, disclosureMap)
            else -> value
        }
    }

    return result
}

private fun sha256Base64Url(input: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(input)
    return encodeToBase64Url(hash)
}


@Suppress("UNCHECKED_CAST")
private fun extractMdocNamespaces(decodedMdoc: co.nstant.`in`.cbor.model.Map): Map<String, Map<String, Any>> {
    val namespaces = mutableMapOf<String, Map<String, Any>>()
    val issuerSigned = getValueFromCborMap(decodedMdoc, "issuerSigned") as? co.nstant.`in`.cbor.model.Map
        ?: return namespaces
    val nameSpaces = getValueFromCborMap(issuerSigned, "nameSpaces") as? co.nstant.`in`.cbor.model.Map
        ?: return namespaces

    for (key in nameSpaces.keys) {
        val nsString = (key as? UnicodeString)?.string ?: continue
        val nsValue = nameSpaces.get(key)
        if (nsValue !is Array) continue

        val elements = mutableMapOf<String, Any>()
        for (item in nsValue.dataItems) {
            val decoded = decodeTaggedCborItem(item) ?: continue
            val elementId = extractStringFromCborMap(decoded as? co.nstant.`in`.cbor.model.Map ?: continue, "elementIdentifier")
                ?: continue
            val elementValue = getValueFromCborMap(decoded, "elementValue")
            if (elementValue != null) {
                val unwrapped = unwrapCborValue(elementValue)
                if (unwrapped != null) {
                    elements[elementId] = unwrapped
                }
            }
        }
        namespaces[nsString] = elements
    }

    return namespaces
}

private fun decodeTaggedCborItem(item: DataItem): DataItem? {
    if (item.tag?.value == 24L && item is ByteString) {
        return try {
            val decoded = CborDecoder(item.bytes.inputStream()).decode()
            decoded.firstOrNull()
        } catch (_: Exception) {
            null
        }
    }
    // Handle the case where the item has a tag but is a different type
    if (item.tag?.value == 24L) {
        // Try to find a ByteString within
        return null
    }
    return null
}

private fun getValueFromCborMap(map: co.nstant.`in`.cbor.model.Map, key: String): DataItem? {
    for (k in map.keys) {
        if (k is UnicodeString && k.string == key) {
            return map.get(k)
        }
    }
    return null
}

internal fun extractStringFromCborMap(map: co.nstant.`in`.cbor.model.Map, key: String): String? {
    val value = getValueFromCborMap(map, key)
    return (value as? UnicodeString)?.string
}

private fun unwrapCborValue(item: DataItem): Any? {
    return when (item) {
        is UnicodeString -> item.string
        is UnsignedInteger -> item.value.toLong()
        is NegativeInteger -> item.value.toLong()
        is DoublePrecisionFloat -> item.value
        is SinglePrecisionFloat -> item.value.toDouble()
        is HalfPrecisionFloat -> item.value.toDouble()
        is SimpleValue -> when (item.simpleValueType) {
            SimpleValueType.TRUE -> true
            SimpleValueType.FALSE -> false
            else -> null
        }
        is ByteString -> item.bytes
        is Array -> item.dataItems.mapNotNull { unwrapCborValue(it) }
        is co.nstant.`in`.cbor.model.Map -> {
            val result = mutableMapOf<String, Any>()
            for (k in item.keys) {
                val keyStr = (k as? UnicodeString)?.string ?: continue
                val value = unwrapCborValue(item.get(k)) ?: continue
                result[keyStr] = value
            }
            result
        }
        else -> null
    }
}
