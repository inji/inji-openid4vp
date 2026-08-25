package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MdocCredentialUtilsTest {

    private val className = "MdocCredentialUtilsTest"

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    @Test
    fun `getMdocDocTypeAndIssuerSigned should throw InvalidData when credential is not a String`() {
        val invalidCredential = 12345 // Not a String

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocTypeAndIssuerSigned(invalidCredential, className)
        }

        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `getMdocDocTypeAndIssuerSigned should throw InvalidData when decoded CBOR is not a Map`() {
        // Create a valid base64url encoded CBOR, but not a Map (an array instead)
        val cborArray = cborArrayOf("test")
        val encodedInvalidCbor = encodeToBase64Url(encodeCbor(cborArray))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocTypeAndIssuerSigned(encodedInvalidCbor, className)
        }

        assertEquals("MDOC credential is not a valid CBOR map", exception.message)
    }

    @Test
    fun `getMdocDocType should throw InvalidData when credential is not a String`() {
        val invalidCredential = mapOf("key" to "value") // Not a String

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(invalidCredential, className)
        }

        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `getMdocDocType should throw InvalidData when decoded CBOR is not a Map`() {
        // Create a valid base64url encoded CBOR, but not a Map
        val cborArray = cborArrayOf("test")
        val encodedInvalidCbor = encodeToBase64Url(encodeCbor(cborArray))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(encodedInvalidCbor, className)
        }

        assertEquals("MDOC credential is not a valid CBOR map", exception.message)
    }

    @Test
    fun `getMdocDocType should throw InvalidData when issuerSigned is not a Map`() {
        // Create a credential with issuerSigned that's not a Map
        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), UnicodeString("not a map"))
        }
        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        }

        assertEquals("issuerSigned is not a valid CBOR map", exception.message)
    }

    @Test
    fun `getIssuerSigned should throw InvalidData when issuerAuth array has less than 3 items`() {
        // Create issuerSigned with issuerAuth array containing only 2 items (missing payload)
        val issuerAuthArray = Array().apply {
            add(ByteString(byteArrayOf(1, 2, 3))) // protected header
            add(CborMap()) // unprotected header
            // Missing payload at index 2
        }

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        }

        assertEquals("issuerAuth payload missing", exception.message)
    }

    @Test
    fun `getIssuerSigned should throw InvalidData when issuerAuth array is empty`() {
        // Create issuerSigned with empty issuerAuth array
        val issuerAuthArray = Array() // Empty array

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        }

        assertEquals("issuerAuth payload missing", exception.message)
    }

    @Test
    fun `getIssuerSigned should throw InvalidData when issuerAuth array has exactly 2 items`() {
        // Create issuerSigned with issuerAuth array containing exactly 2 items
        val issuerAuthArray = Array().apply {
            add(ByteString(byteArrayOf(1, 2, 3))) // protected header
            add(CborMap()) // unprotected header
            // Index 2 is missing
        }

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        }

        assertEquals("issuerAuth payload missing", exception.message)
    }

    @Test
    fun `getIssuerSigned should throw InvalidData when payload at index 2 is not ByteString`() {
        // Create a minimal MSO structure
        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
            put(UnicodeString("version"), UnicodeString("1.0"))
        }

        val msoBytes = encodeCbor(mso)

        // Create issuerAuth array with payload at index 2 that's not a ByteString
        val issuerAuthArray = Array().apply {
            add(ByteString(byteArrayOf(1, 2, 3))) // protected header
            add(CborMap()) // unprotected header
            add(UnicodeString("not a bytestring")) // payload is not ByteString
        }

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        }

        assertEquals("issuerAuth payload missing", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg should throw InvalidData when issuerAuth array is malformed`() {
        // Create issuerSigned with malformed issuerAuth (less than 3 items)
        val issuerAuthArray = Array().apply {
            add(ByteString(byteArrayOf(1, 2, 3)))
            // Missing items
        }

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(encodedCredential, className)
        }

        assertEquals("issuerAuth payload missing", exception.message)
    }

    @Test
    fun `getIssuerSigned should succeed when issuerAuth array has exactly 3 items with valid payload`() {
        // Create a minimal valid MSO structure
        val deviceKey = CborMap()
        val deviceKeyInfo = CborMap().apply {
            put(UnicodeString("deviceKey"), deviceKey)
        }

        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
            put(UnicodeString("version"), UnicodeString("1.0"))
            put(UnicodeString("deviceKeyInfo"), deviceKeyInfo)
        }

        val msoBytes = encodeCbor(mso)

        // Create valid issuerAuth array with 3 items
        val issuerAuthArray = Array().apply {
            add(ByteString(byteArrayOf(1, 2, 3))) // protected header
            add(CborMap()) // unprotected header
            add(ByteString(msoBytes)) // payload as ByteString
        }

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        // This should not throw an exception
        val result = MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        assertEquals("org.iso.18013.5.1.mDL", result)
    }

    @Test
    fun `getIssuerSigned should succeed when issuerAuth array has more than 3 items`() {
        // Create a minimal valid MSO structure
        val deviceKey = CborMap()
        val deviceKeyInfo = CborMap().apply {
            put(UnicodeString("deviceKey"), deviceKey)
        }

        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
            put(UnicodeString("version"), UnicodeString("1.0"))
            put(UnicodeString("deviceKeyInfo"), deviceKeyInfo)
        }

        val msoBytes = encodeCbor(mso)

        // Create issuerAuth array with more than 3 items (COSE_Sign1 with signature)
        val issuerAuthArray = Array().apply {
            add(ByteString(byteArrayOf(1, 2, 3))) // protected header
            add(CborMap()) // unprotected header
            add(ByteString(msoBytes)) // payload
            add(ByteString(byteArrayOf(4, 5, 6))) // signature (4th item)
        }

        val issuerSigned = CborMap().apply {
            put(UnicodeString("issuerAuth"), issuerAuthArray)
        }

        val decodedMdoc = CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val encodedCredential = encodeToBase64Url(encodeCbor(decodedMdoc))

        // This should not throw an exception
        val result = MdocCredentialUtils.getMdocDocType(encodedCredential, className)
        assertEquals("org.iso.18013.5.1.mDL", result)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg maps COSE alg to JOSE algorithm`() {
        mapOf(-7L to "ES256", -8L to "EdDSA").forEach { (coseAlg, expectedJoseAlg) ->
            val credential = mdocWithDeviceKey(deviceKey(alg = NegativeInteger(coseAlg)))

            val (keyRef, alg) = MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)

            assertEquals(expectedJoseAlg, alg)
            assertTrue(keyRef.isNotEmpty())
        }
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg rejects an unsupported COSE alg`() {
        val credential = mdocWithDeviceKey(deviceKey(alg = UnsignedInteger(5)))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)
        }
        assertEquals("Unsupported COSE alg 5", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg rejects a non-integer COSE alg`() {
        val credential = mdocWithDeviceKey(deviceKey(alg = UnicodeString("ES256")))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)
        }
        assertEquals("Invalid alg type", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg infers the algorithm from the curve when alg is absent`() {
        mapOf(1L to "ES256", 6L to "EdDSA").forEach { (curve, expectedJoseAlg) ->
            val credential = mdocWithDeviceKey(deviceKey(crv = UnsignedInteger(curve)))

            assertEquals(expectedJoseAlg, MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className).second)
        }
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg rejects an unsupported curve`() {
        val credential = mdocWithDeviceKey(deviceKey(crv = UnsignedInteger(9)))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)
        }
        assertEquals("Unsupported crv 9", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg rejects a non-unsigned curve label`() {
        val credential = mdocWithDeviceKey(deviceKey(crv = NegativeInteger(-1)))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)
        }
        assertEquals("Invalid crv type", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg requires a curve when alg is absent`() {
        val credential = mdocWithDeviceKey(CborMap().apply {
            put(UnsignedInteger(1), UnsignedInteger(2))
        })

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)
        }
        assertEquals("crv missing for alg inference", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg accepts an untagged issuerAuth payload`() {
        val credential = mdocWithDeviceKey(deviceKey(alg = NegativeInteger(-7)), tagPayload = false)

        assertEquals("ES256", MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className).second)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg derives the key reference from the device key`() {
        val key = deviceKey(alg = NegativeInteger(-7))
        val credential = mdocWithDeviceKey(key)

        val (keyRef, _) = MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)

        assertEquals(encoder.encodeToString(encodeCbor(key)), keyRef)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg rejects a credential with neither issuerAuth nor issuerSigned`() {
        val credential = base64(encodeCbor(CborMap().apply {
            put(UnicodeString("other"), UnicodeString("value"))
        }))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(credential, className)
        }
        assertEquals("Invalid mDoc structure", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg requires issuerAuth to be a COSE_Sign1 array`() {
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("issuerAuth"), UnicodeString("not-an-array"))
            })
        }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(base64(encodeCbor(root)), className)
        }
        assertEquals("issuerAuth not COSE_Sign1", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg requires a tag 24 payload to wrap a byte string`() {
        val taggedText = UnicodeString("tagged-but-not-bytes").apply { setTag(24L) }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(mdocFromPayload(ByteString(encodeCbor(taggedText))), className)
        }
        assertEquals("Tag 24 inner not bstr", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg requires the MSO to be a map`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(
                mdocFromPayload(ByteString(encodeCbor(UnicodeString("not-a-map")))),
                className
            )
        }
        assertEquals("MSO not map after unwrap", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg requires deviceKeyInfo`() {
        val mso = CborMap().apply { put(UnicodeString("version"), UnicodeString("1.0")) }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(mdocFromPayload(taggedPayload(mso)), className)
        }
        assertEquals("deviceKeyInfo missing", exception.message)
    }

    @Test
    fun `extractMdocKeyReferenceAndAlg requires deviceKey`() {
        val mso = CborMap().apply {
            put(UnicodeString("deviceKeyInfo"), CborMap())
        }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(mdocFromPayload(taggedPayload(mso)), className)
        }
        assertEquals("deviceKey missing", exception.message)
    }

    private fun deviceKey(alg: DataItem? = null, crv: DataItem? = null): CborMap =
        CborMap().apply {
            put(UnsignedInteger(1), UnsignedInteger(2))
            crv?.let { put(NegativeInteger(-1), it) }
            alg?.let { put(UnsignedInteger(3), it) }
        }

    private fun taggedPayload(mso: CborMap) = ByteString(encodeCbor(taggedCbor24(mso)))

    private fun mdocFromPayload(payload: DataItem): String {
        val issuerAuth = CborArray().apply {
            add(ByteString(byteArrayOf()))
            add(CborMap())
            add(payload)
            add(ByteString(byteArrayOf()))
        }
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("issuerAuth"), issuerAuth)
            })
        }
        return base64(encodeCbor(root))
    }

    private fun mdocWithDeviceKey(key: DataItem, tagPayload: Boolean = true): String {
        val mso = CborMap().apply {
            put(UnicodeString("deviceKeyInfo"), CborMap().apply {
                put(UnicodeString("deviceKey"), key)
            })
        }
        val payload =
            if (tagPayload) taggedPayload(mso) else ByteString(encodeCbor(mso))
        return mdocFromPayload(payload)
    }

    private fun base64(bytes: ByteArray) = encoder.encodeToString(bytes)

    @Test
    fun `getMdocDocType rejects an MSO without a docType`() {
        val credential = mdocFromPayload(taggedPayload(CborMap().apply {
            put(UnicodeString("version"), UnicodeString("1.0"))
        }))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocType(credential, className)
        }
        assertEquals("docType missing or invalid in credential", exception.message)
    }

    @Test
    fun `getMdocDocTypeAndIssuerSigned rejects an MSO without a docType`() {
        val credential = mdocFromPayload(taggedPayload(CborMap().apply {
            put(UnicodeString("version"), UnicodeString("1.0"))
        }))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocTypeAndIssuerSigned(credential, className)
        }
        assertEquals("docType missing or invalid in credential", exception.message)
    }

    @Test
    fun `getMdocDocTypeAndIssuerSigned rejects an issuerSigned that is not a map`() {
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), UnicodeString("not-a-map"))
        }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            MdocCredentialUtils.getMdocDocTypeAndIssuerSigned(base64(encodeCbor(root)), className)
        }
        assertEquals("issuerSigned is not a valid CBOR map", exception.message)
    }

    @Test
    fun `getMdocDocTypeAndIssuerSigned returns the docType and issuerSigned of a well formed credential`() {
        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
        }

        val encodedCredential = mdocFromPayload(taggedPayload(mso))

        val (credential, docType, issuerSigned) =
            MdocCredentialUtils.getMdocDocTypeAndIssuerSigned(encodedCredential, className)

        assertEquals("org.iso.18013.5.1.mDL", docType)
        assertEquals(encodedCredential, credential)
        assertTrue(issuerSigned is CborMap)
    }
}
