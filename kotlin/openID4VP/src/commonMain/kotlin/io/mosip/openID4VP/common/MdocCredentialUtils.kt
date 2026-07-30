package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.dcql.evaluator.extractStringFromCborMap
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import java.io.ByteArrayInputStream

internal object MdocCredentialUtils {
    fun getMdocDocTypeAndIssuerSigned(credential: Any, className: String): Triple<String, String, DataItem> {
        val mdocCredential = credential as? String
            ?: throw InvalidData("MDOC credential is not a String",
                className
            )
        val decodedMdoc = decodeCbor(decodeFromBase64Url(mdocCredential)) as Map
        val issuerSigned = getIssuerSigned(decodedMdoc, className)
        val docType = getMdocDocType(issuerSigned, className)

        return Triple(mdocCredential, docType, issuerSigned)
    }
    private fun getMdocDocType(issuerSigned: DataItem, className: String): String {
        val mso: Map = getMso(issuerSigned as Map, className)

        return (extractStringFromCborMap(mso, "docType")
            ?: throw InvalidData(
                "docType missing or invalid in credential", className
            ))
    }

    fun getMdocDocType(credential: Any, className: String): String {
        val mdocCredential = credential as? String
            ?: throw InvalidData(
                "MDOC credential is not a String", className
            )
        val decodedMdoc = decodeCbor(decodeFromBase64Url(mdocCredential)) as Map
        val issuerSigned = getIssuerSigned(decodedMdoc, className) as Map
        val mso: Map = getMso(issuerSigned, className)

        return (extractStringFromCborMap(mso, "docType")
            ?: throw InvalidData(
                "docType missing or invalid in credential", className
            ))
    }

    fun getIssuerSigned(decodedMdoc: Map, className: String): DataItem {
        return if (decodedMdoc["issuerAuth"] != null) {
            decodedMdoc
        } else if (decodedMdoc["issuerSigned"] != null) {
            decodedMdoc["issuerSigned"]!!
        } else {
            throw InvalidData(
                "Invalid mDoc structure",
                className
            )
        }
    }

    operator fun DataItem.get(name: String): DataItem? {
        check(this.majorType == MajorType.MAP)
        this as Map
        if (this.keys.contains(UnicodeString(name)))
            return this.get(UnicodeString(name))
        return null
    }

    operator fun DataItem.get(index: Int): DataItem {
        check(this.majorType == MajorType.ARRAY)
        this as Array
        return this.dataItems[index]
    }

    internal fun resolveMdocKeyAndAlg(
        mdocCredential: String,
        className: String
    ): Pair<String, String> =
        extractMdocKeyReferenceAndAlg(mdocCredential, className)

    private fun extractMdocKeyReferenceAndAlg(
        mdocCredential: String,
        className: String
    ): Pair<String, String> {
        val decoded = getDecodedMdocCredential(mdocCredential)

        val issuerSigned = getIssuerSigned(decoded, className) as Map

        val mso = getMso(issuerSigned, className)

        val deviceKeyInfo = mso[UnicodeString("deviceKeyInfo")] as? Map
            ?: throw InvalidData("deviceKeyInfo missing", className)

        val deviceKey = deviceKeyInfo[UnicodeString("deviceKey")] as? Map
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

    private fun getMso(
        issuerSigned: Map,
        className: String
    ): Map {
        val issuerAuthArray =
            issuerSigned[UnicodeString("issuerAuth")] as? Array
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

        val mso = msoDataItem as? Map
            ?: throw InvalidData("MSO not map after unwrap", className)
        return mso
    }
}