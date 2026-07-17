package io.mosip.openID4VP.common

import com.fasterxml.jackson.annotation.JsonProperty
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import kotlin.test.*
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import io.mosip.openID4VP.constants.FormatType
import java.security.MessageDigest
import kotlin.test.assertNull

class UtilsTest {

    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val className = "UtilsTest"

    @BeforeTest
    fun mockBase64() {
        unmockkAll()
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers { encoder.encodeToString(firstArg<ByteArray>()) }
    }

    @AfterTest
    fun unmock() {
        unmockkAll()
    }

    @Test
    fun `isValidUrl should return true for valid URLs per RFC 3986`() {
        val validUrls = listOf(
            "https://example.com/path?query=value#fragment",
            // RFC 3986 structure: port + multi-segment path + query + fragment
            "https://example.com:8042/over/there?name=ferret#nose",
            // percent-encoded octets in path and query
            "https://example.com/a%20b?q=hello%20world",
            // empty path segment
            "https://example.com//empty/seg",
            // '/', '?' and '@' allowed within query and fragment
            "https://example.com/p?a=1/2&b=x?y#f/g?h"
        )

        validUrls.forEach { url -> assertTrue(isValidUrl(url), "expected valid: $url") }
    }

    @Test
    fun `isValidUrl should return false for invalid URL`() {

        val testUrls = listOf(
            "www.example.com",
            "http://example.com/space here",
            "http://",
            "https://example",
            "http://example.com/file%/name",
            "http://example.com:99999",
            "http:///example.com",
            "http://example.com/search?q=hello%20world#@fragment",
            "http://:8080",
            "",
            "https://example.com/invalid|character",
            // non-https scheme is rejected even with valid RFC 3986 structure
            "foo://example.com:8042/over/there?name=ferret#nose",
            // malformed percent-encoding (not followed by two hex digits)
            "https://example.com/file%/name",
            // whitespace is not allowed
            "https://example.com/space here",
            // trailing newline must not be accepted
            "https://example.com/path\n"
        )

        testUrls.forEach { url -> assertFalse(isValidUrl(url), "expected invalid: $url") }
    }

    @Test
    fun `convertJsonToMap should correctly parse JSON string`() {
        val json = "{\"key\":\"value\"}"
        val result = convertJsonToMap(json)
        assertEquals("value", result["key"])
    }

    @Test
    fun `isJWT should return true for valid JWT`() {
        val jwt = "header.payload.signature"
        assertTrue(isJWS(jwt))
    }

    @Test
    fun `isJWT should return false for invalid JWT`() {
        val jwt = "invalid.jwt"
        assertFalse(isJWS(jwt))
    }

    @Test
    fun `determineHttpMethod should return correct HTTP method`() {
        assertEquals(HttpMethod.GET, determineHttpMethod("get"))
        assertEquals(HttpMethod.POST, determineHttpMethod("post"))
    }

    @Test
    fun `determineHttpMethod should throw exception for unsupported method`() {
        assertFailsWith<IllegalArgumentException> {
            determineHttpMethod("put")
        }
    }

    @Test
    fun `getStringValue should return correct string value from map`() {
        val map = mapOf("key" to "value")
        assertEquals("value", getStringValue(map, "key"))
        assertNull(getStringValue(map, "nonexistent"))
    }

    internal data class MockDataClass(
        val key: String,
        @JsonProperty("key_with_more_than_one_word")
        val keyWithMoreThanOneWord: String,
        @JsonProperty("nullable_field")
        val nullableField: String? = null,
    )

    @Test

    fun `should serialize data class instance to JSON with all properties specified`() {
        val mockDataClass = MockDataClass(
            key = "id_credential",
            keyWithMoreThanOneWord = "ldp_vp",
            nullableField = "value",
        )

        val descriptorMapJson = encodeToJsonString<MockDataClass>(
            mockDataClass,
            "mockDataClass",
            "UtilsTest"
        )
        "{\"key\":\"id_credential\",\"number\":1,\"key_with_more_than_one_word\":\"ldp_vp\"}"

        assertEquals(
            "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\",\"nullable_field\":\"value\"}",
            descriptorMapJson
        )
    }

    @Test
    fun `should serialize data class without nullable fields to JSON successfully`() {
        val mockDataClass = MockDataClass(
            key = "id_credential",
            keyWithMoreThanOneWord = "ldp_vp",
        )

        val descriptorMapJson = encodeToJsonString<MockDataClass>(
            mockDataClass,
            "mockDataClass",
            "UtilsTest"
        )

        assertEquals(
            "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\"}",
            descriptorMapJson
        )
    }

    @Test
    fun toHex_emptyByteArray_returnsEmptyString() {
        val emptyArray = ByteArray(0)
        assertEquals("", emptyArray.toHex())
    }

    @Test
    fun toHex_simpleByteArray_returnsCorrectHexString() {
        val bytes = byteArrayOf(10, 20, 30, 40, 50)
        assertEquals("0a141e2832", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithSmallValues_includesLeadingZeros() {
        val bytes = byteArrayOf(0, 1, 15)
        assertEquals("00010f", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithNegativeValues_handlesCorrectly() {
        val bytes = byteArrayOf(-1, -128)
        assertEquals("ff80", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithMixedValues_convertsCorrectly() {
        val bytes = byteArrayOf(0, 15, 16, 127, -128, -1)
        assertEquals("000f107f80ff", bytes.toHex())
    }

    @Test
    fun testResolveFromJwksUri() {
        val jwksUri = "https://mock-verifier.com/.well-known/jwks.json"
        val keyId = "f4a0c7f3f1b1e3a1b1e3a1b1e3a1b1e3a1b1e3a1b"
        mockkObject(NetworkManagerClient)
        val mockJwksResponse = """
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "-Fy3lMapzR3wpaYNCFq29GDEn_NoR3pBsc511q1Cxqw",
                        "alg": "EdDSA",
                        "kid": "f4a0c7f3f1b1e3a1b1e3a1b1e3a1b1e3a1b1e3a1b",
                        "use": "sig"
                    }
                ]
            }
        """.trimIndent()
        every {
            NetworkManagerClient.sendHTTPRequest(jwksUri, HttpMethod.GET)
        } returns NetworkResponse(
            200, mockJwksResponse,
            headers = mapOf()
        )

        val publicKey = resolveJwksFromUri(jwksUri, keyId)

        assertNotNull(publicKey)
    }

    @Test
    fun `resolveMdocKeyAndAlg maps COSE alg to JOSE algorithm`() {
        mapOf(-7L to "ES256", -8L to "EdDSA").forEach { (coseAlg, expectedJoseAlg) ->
            val credential = mdocWithDeviceKey(deviceKey(alg = NegativeInteger(coseAlg)))

            val (keyRef, alg) = resolveMdocKeyAndAlg(credential, className)

            assertEquals(expectedJoseAlg, alg)
            assertTrue(keyRef.isNotEmpty())
        }
    }

    @Test
    fun `resolveMdocKeyAndAlg rejects an unsupported COSE alg`() {
        val credential = mdocWithDeviceKey(deviceKey(alg = UnsignedInteger(5)))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(credential, className)
        }
        assertEquals("Unsupported COSE alg 5", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg rejects a non-integer COSE alg`() {
        val credential = mdocWithDeviceKey(deviceKey(alg = UnicodeString("ES256")))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(credential, className)
        }
        assertEquals("Invalid alg type", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg infers the algorithm from the curve when alg is absent`() {
        mapOf(1L to "ES256", 6L to "EdDSA").forEach { (curve, expectedJoseAlg) ->
            val credential = mdocWithDeviceKey(deviceKey(crv = UnsignedInteger(curve)))

            assertEquals(expectedJoseAlg, resolveMdocKeyAndAlg(credential, className).second)
        }
    }

    @Test
    fun `resolveMdocKeyAndAlg rejects an unsupported curve`() {
        val credential = mdocWithDeviceKey(deviceKey(crv = UnsignedInteger(9)))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(credential, className)
        }
        assertEquals("Unsupported crv 9", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg rejects a non-unsigned curve label`() {
        val credential = mdocWithDeviceKey(deviceKey(crv = NegativeInteger(-1)))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(credential, className)
        }
        assertEquals("Invalid crv type", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires a curve when alg is absent`() {
        val credential = mdocWithDeviceKey(CborMap().apply {
            put(UnsignedInteger(1), UnsignedInteger(2))
        })

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(credential, className)
        }
        assertEquals("crv missing for alg inference", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg accepts an untagged issuerAuth payload`() {
        val credential = mdocWithDeviceKey(deviceKey(alg = NegativeInteger(-7)), tagPayload = false)

        assertEquals("ES256", resolveMdocKeyAndAlg(credential, className).second)
    }

    @Test
    fun `resolveMdocKeyAndAlg derives the key reference from the device key`() {
        val key = deviceKey(alg = NegativeInteger(-7))
        val credential = mdocWithDeviceKey(key)

        val (keyRef, _) = resolveMdocKeyAndAlg(credential, className)

        assertEquals(encoder.encodeToString(encodeCbor(key)), keyRef)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires issuerSigned`() {
        val credential = base64(encodeCbor(CborMap().apply {
            put(UnicodeString("other"), UnicodeString("value"))
        }))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(credential, className)
        }
        assertEquals("issuerSigned missing", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires issuerAuth to be a COSE_Sign1 array`() {
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("issuerAuth"), UnicodeString("not-an-array"))
            })
        }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(base64(encodeCbor(root)), className)
        }
        assertEquals("issuerAuth not COSE_Sign1", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires the issuerAuth payload to be a byte string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(mdocFromPayload(UnicodeString("not-bytes")), className)
        }
        assertEquals("issuerAuth payload missing", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires a tag 24 payload to wrap a byte string`() {
        val taggedText = UnicodeString("tagged-but-not-bytes").apply { setTag(24L) }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(mdocFromPayload(ByteString(encodeCbor(taggedText))), className)
        }
        assertEquals("Tag 24 inner not bstr", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires the MSO to be a map`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(
                mdocFromPayload(ByteString(encodeCbor(UnicodeString("not-a-map")))),
                className
            )
        }
        assertEquals("MSO not map after unwrap", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires deviceKeyInfo`() {
        val mso = CborMap().apply { put(UnicodeString("version"), UnicodeString("1.0")) }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(mdocFromPayload(taggedPayload(mso)), className)
        }
        assertEquals("deviceKeyInfo missing", exception.message)
    }

    @Test
    fun `resolveMdocKeyAndAlg requires deviceKey`() {
        val mso = CborMap().apply {
            put(UnicodeString("deviceKeyInfo"), CborMap())
        }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveMdocKeyAndAlg(mdocFromPayload(taggedPayload(mso)), className)
        }
        assertEquals("deviceKey missing", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg honours an explicit alg on the confirmation jwk`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "EC", "alg" to "ES512"))))

        val (jwkJson, alg) = resolveSdJwtKeyAndAlg(credential, className)

        assertEquals("ES512", alg)
        assertTrue(jwkJson.contains("\"kty\":\"EC\""))
    }

    @Test
    fun `resolveSdJwtKeyAndAlg infers the algorithm from kty and crv`() {
        val cases = mapOf(
            ("OKP" to "Ed25519") to "EdDSA",
            ("EC" to "P-256") to "ES256",
            ("EC" to "P-384") to "ES384",
            ("EC" to "P-521") to "ES512",
            ("EC" to "secp256k1") to "ES256K"
        )

        cases.forEach { (key, expectedAlg) ->
            val credential = sdJwt(
                mapOf("cnf" to mapOf("jwk" to mapOf("kty" to key.first, "crv" to key.second)))
            )
            assertEquals(
                expectedAlg,
                resolveSdJwtKeyAndAlg(credential, className).second,
                "kty=${key.first} crv=${key.second}"
            )
        }
    }

    @Test
    fun `resolveSdJwtKeyAndAlg infers RS256 for an RSA confirmation key`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "rsa"))))

        assertEquals("RS256", resolveSdJwtKeyAndAlg(credential, className).second)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg requires kty on the confirmation jwk`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("crv" to "P-256"))))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("JWK missing 'kty' field", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg rejects a jwk whose algorithm cannot be determined`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "EC", "crv" to "P-999"))))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("Cannot determine algorithm from JWK (kty=EC, crv=P-999)", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg requires a cnf claim`() {
        val credential = sdJwt(mapOf("vct" to "employee"))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("cnf missing in SD-JWT", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg requires cnf to carry a jwk or a kid`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("other" to "value")))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("cnf must contain either 'jwk' or 'kid'", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg reads the confirmation key from the jwt ahead of disclosures`() {
        val credential =
            sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "OKP", "crv" to "Ed25519")))) +
                "~disclosure-one~disclosure-two"

        assertEquals("EdDSA", resolveSdJwtKeyAndAlg(credential, className).second)
    }

    private fun base64(bytes: ByteArray) = encoder.encodeToString(bytes)

    private fun deviceKey(alg: DataItem? = null, crv: DataItem? = null): CborMap =
        CborMap().apply {
            put(UnsignedInteger(1), UnsignedInteger(2))
            crv?.let { put(NegativeInteger(-1), it) }
            alg?.let { put(UnsignedInteger(3), it) }
        }

    private fun taggedPayload(mso: DataItem) = ByteString(encodeCbor(tagEncodedCbor(mso)))

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

    private fun sdJwt(payload: Map<String, Any>): String {
        val header = base64(getObjectMapper().writeValueAsBytes(mapOf("alg" to "none")))
        val body = base64(getObjectMapper().writeValueAsBytes(payload))
        return "$header.$body.signature"
    }

    @Test
    fun `hashData returns the base64url sha-256 digest by default`() {
        val expected = encoder.encodeToString(
            MessageDigest.getInstance("SHA-256").digest("payload".toByteArray(Charsets.UTF_8))
        )

        assertEquals(expected, hashData("payload"))
    }

    @Test
    fun `hashData honours an explicit algorithm`() {
        val expected = encoder.encodeToString(
            MessageDigest.getInstance("SHA-512").digest("payload".toByteArray(Charsets.UTF_8))
        )

        assertEquals(expected, hashData("payload", "SHA-512"))
    }

    @Test
    fun `hashData is stable across calls`() {
        assertEquals(hashData("payload"), hashData("payload"))
    }

    @Test
    fun `resolveJwksFromUri wraps a non-success status`() {
        mockkObject(NetworkManagerClient)
        every { NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.GET) } returns
            NetworkResponse(500, "boom", headers = emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveJwksFromUri("https://verifier.example/jwks.json", className)
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT, exception.errorCode)
        assertTrue(exception.message.contains("Error while fetching jwks information, status code: 500"))
    }

    @Test
    fun `resolveJwksFromUri wraps a transport failure`() {
        mockkObject(NetworkManagerClient)
        every { NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.GET) } throws
            RuntimeException("connection refused")

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveJwksFromUri("https://verifier.example/jwks.json", className)
        }

        assertTrue(exception.message.contains("connection refused"))
    }

    @Test
    fun `resolveJwksFromUri wraps an unparseable body`() {
        mockkObject(NetworkManagerClient)
        every { NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.GET) } returns
            NetworkResponse(200, "not-json", headers = emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveJwksFromUri("https://verifier.example/jwks.json", className)
        }

        assertTrue(exception.message.startsWith("Public key extraction failed"))
    }

    @Test
    fun `encodeToMultibaseBase58btc prefixes the multibase marker`() {
        assertTrue(encodeToMultibaseBase58btc(byteArrayOf(1, 2, 3)).startsWith("z"))
    }

    @Test
    fun `encodeToMultibaseBase58btc encodes leading zero bytes as ones`() {
        assertEquals("z11", encodeToMultibaseBase58btc(byteArrayOf(0, 0)))
        assertTrue(encodeToMultibaseBase58btc(byteArrayOf(0, 1)).startsWith("z1"))
    }

    @Test
    fun `encodeToMultibaseBase58btc encodes an empty array as the bare marker`() {
        assertEquals("z", encodeToMultibaseBase58btc(byteArrayOf()))
    }

    @Test
    fun `encodeToMultibaseBase58btc is deterministic`() {
        val bytes = "signature".toByteArray(Charsets.UTF_8)

        assertEquals(encodeToMultibaseBase58btc(bytes), encodeToMultibaseBase58btc(bytes))
    }

    @Test
    fun `validate accepts a populated value`() {
        validate("client_id", "verifier-1", className)
    }

    @Test
    fun `validate rejects a null value as missing input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            validate("client_id", null, className)
        }
        assertEquals("Missing Input: client_id param is required", exception.message)
    }

    @Test
    fun `validate rejects empty and literal null values as invalid input`() {
        assertFailsWith<OpenID4VPExceptions.InvalidInput> { validate("client_id", "", className) }
        assertFailsWith<OpenID4VPExceptions.InvalidInput> { validate("client_id", "null", className) }
    }

    @Test
    fun `validate propagates the notifyVerifier flag`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            validate("client_id", null, className, notifyVerifier = false)
        }
        assertEquals(false, exception.notifyVerifier)
    }

    @Test
    fun `hexToByteArray round trips with toHex`() {
        val bytes = byteArrayOf(0, 15, 16, 127, -128, -1)

        assertEquals(bytes.toList(), hexToByteArray(bytes.toHex()).toList())
    }

    @Test
    fun `createNestedPath returns null when no nested path is given`() {
        assertNull(createNestedPath("input-1", null, FormatType.LDP_VC))
    }

    @Test
    fun `createNestedPath builds a nested descriptor path`() {
        val nested = createNestedPath("input-1", "$.verifiableCredential[0]", FormatType.LDP_VC)

        assertEquals("input-1", nested?.id)
        assertEquals(FormatType.LDP_VC.value, nested?.format)
        assertEquals("$.verifiableCredential[0]", nested?.path)
    }

    @Test
    fun `createDescriptorMapPath indexes the root path`() {
        assertEquals("$[0]", createDescriptorMapPath(0))
        assertEquals("$[3]", createDescriptorMapPath(3))
    }

    @Test
    fun `generateNonce produces distinct values of the requested entropy`() {
        val first = generateNonce()
        val second = generateNonce()

        assertTrue(first != second)
        assertEquals(16, Base64.getUrlDecoder().decode(first).size)
        assertEquals(32, Base64.getUrlDecoder().decode(generateNonce(32)).size)
    }

    @Test
    fun `getObjectMapper returns the shared instance`() {
        assertTrue(getObjectMapper() === getObjectMapper())
    }
}
