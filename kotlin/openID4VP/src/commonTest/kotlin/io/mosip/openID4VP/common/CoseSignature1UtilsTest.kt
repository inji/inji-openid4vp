package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.cose.CoseSignature1Utils
import kotlin.test.*

class CoseSignature1UtilsTest {

    @Test
    fun `createSignature1Structure should create valid Sig_structure with default ES256 algorithm`() {
        val payload = "test payload".toByteArray()
        val result = CoseSignature1Utils.createSignature1Structure(payload, "ES256")

        // Verify result is not empty
        assertTrue(result.isNotEmpty())

        // Decode and verify structure
        val decoded = decodeCbor(result)
        assertTrue(decoded is Array)

        val sigArray = decoded as Array
        assertEquals(4, sigArray.dataItems.size, "Sig_structure should have 4 elements")

        // Element 0: context = "Signature1"
        assertEquals("Signature1", sigArray.dataItems[0].toString())

        // Element 1: body_protected (serialized protected header)
        assertTrue(sigArray.dataItems[1] is ByteString)
        val protectedHeader = sigArray.dataItems[1] as ByteString
        val protectedHeaderMap = decodeCbor(protectedHeader.bytes) as Map

        // Verify alg = -7 (ES256)
        val algKey = UnsignedInteger(1)
        val algValue = protectedHeaderMap.get(algKey) as NegativeInteger
        assertEquals(-7L, algValue.value.toLong())

        // Element 2: external_aad (empty)
        assertTrue(sigArray.dataItems[2] is ByteString)
        val externalAad = sigArray.dataItems[2] as ByteString
        assertEquals(0, externalAad.bytes.size)

        // Element 3: payload
        assertTrue(sigArray.dataItems[3] is ByteString)
        val payloadBstr = sigArray.dataItems[3] as ByteString
        assertContentEquals(payload, payloadBstr.bytes)
    }

    @Test
    fun `createSignature1Structure should accept custom COSE alg value`() {
        val payload = "test".toByteArray()
        val customAlg = -999L
        val result = CoseSignature1Utils.createSignature1Structure(payload, "ES256", customAlg)

        val decoded = decodeCbor(result) as Array
        val protectedHeader = decoded.dataItems[1] as ByteString
        val protectedHeaderMap = decodeCbor(protectedHeader.bytes) as Map

        // Verify custom alg
        val algValue = protectedHeaderMap.get(UnsignedInteger(1)) as NegativeInteger
        assertEquals(customAlg, algValue.value.toLong())
    }

    @Test
    fun `createSignature1Structure should handle empty payload`() {
        val payload = ByteArray(0)
        val result = CoseSignature1Utils.createSignature1Structure(payload, "ES256")

        assertTrue(result.isNotEmpty())

        val decoded = decodeCbor(result) as Array
        assertEquals(4, decoded.dataItems.size)

        // Verify empty payload is properly encoded
        val payloadBstr = decoded.dataItems[3] as ByteString
        assertEquals(0, payloadBstr.bytes.size)
    }

    @Test
    fun `createSignature1Structure should throw for unsupported algorithm`() {
        val payload = "test".toByteArray()
        val exception = assertFailsWith<IllegalArgumentException> {
            CoseSignature1Utils.createSignature1Structure(payload, "UNSUPPORTED_ALG")
        }
        assertTrue(exception.message!!.contains("Unsupported signing algorithm"))
    }

    // Tests for createCoseSign1

    @Test
    fun `createCoseSign1 should create valid COSE_Sign1 structure with ES256`() {
        val signature = ByteArray(64) { it.toByte() }
        val result = CoseSignature1Utils.createCoseSign1("ES256", signature)

        assertTrue(result is Array)
        val coseArray = result as Array
        assertEquals(4, coseArray.dataItems.size, "COSE_Sign1 should have 4 elements")

        // Element 0: protected header (bstr)
        assertTrue(coseArray.dataItems[0] is ByteString)
        val protectedHeader = coseArray.dataItems[0] as ByteString
        val protectedHeaderMap = decodeCbor(protectedHeader.bytes) as Map

        // Verify alg = -7 (ES256)
        val algValue = protectedHeaderMap.get(UnsignedInteger(1)) as NegativeInteger
        assertEquals(-7L, algValue.value.toLong())

        // Element 1: unprotected header (empty map)
        assertTrue(coseArray.dataItems[1] is Map)
        val unprotectedHeader = coseArray.dataItems[1] as Map
        assertEquals(0, unprotectedHeader.keys.size)

        // Element 2: payload (nil)
        assertNull(coseArray.dataItems[2])

        // Element 3: signature
        assertTrue(coseArray.dataItems[3] is ByteString)
        val signatureBstr = coseArray.dataItems[3] as ByteString
        assertContentEquals(signature, signatureBstr.bytes)
    }

    @Test
    fun `createCoseSign1 should handle empty signature`() {
        val signature = ByteArray(0)
        val result = CoseSignature1Utils.createCoseSign1("ES256", signature)

        val coseArray = result as Array
        val signatureBstr = coseArray.dataItems[3] as ByteString
        assertEquals(0, signatureBstr.bytes.size)
    }

    @Test
    fun `createCoseSign1 should throw for unsupported algorithm`() {
        val signature = ByteArray(64)
        val exception = assertFailsWith<IllegalArgumentException> {
            CoseSignature1Utils.createCoseSign1("INVALID_ALG", signature)
        }
        assertTrue(exception.message!!.contains("Unsupported signing algorithm"))
    }

    @Test
    fun `createCoseSign1 result should be encodable to CBOR`() {
        val signature = ByteArray(64) { it.toByte() }
        val result = CoseSignature1Utils.createCoseSign1("ES256", signature)

        // Should be able to encode the result
        val encoded = encodeCbor(result)
        assertTrue(encoded.isNotEmpty())

        // Should be able to decode it back
        val decoded = decodeCbor(encoded)
        assertTrue(decoded is Array)
        assertEquals(4, (decoded as Array).dataItems.size)
    }
}
