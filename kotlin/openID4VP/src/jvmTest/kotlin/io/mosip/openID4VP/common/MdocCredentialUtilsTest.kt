package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.Map as CborMap
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MdocCredentialUtilsTest {

    private val className = "MdocCredentialUtilsTest"

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
}
