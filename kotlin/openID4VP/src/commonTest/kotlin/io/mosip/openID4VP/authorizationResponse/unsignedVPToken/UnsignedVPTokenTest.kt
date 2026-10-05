package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.constants.FormatType
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class UnsignedVPTokenTest {

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    @BeforeTest
    fun mockEncoder() {
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers { encoder.encodeToString(firstArg<ByteArray>()) }
    }

    @AfterTest
    fun unmock() {
        unmockkAll()
    }

    @Test
    fun `treats tokens with identical content as equal`() {
        val first = token()
        val second = token()

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun `is equal to itself`() {
        val token = token()

        assertTrue(token == token)
    }

    @Test
    fun `is not equal to a value of another type`() {
        assertFalse(token().equals("not-a-token"))
    }

    @Test
    fun `compares dataToSign by content rather than identity`() {
        val first = token(dataToSign = byteArrayOf(1, 2, 3))
        val second = token(dataToSign = byteArrayOf(1, 2, 3))

        assertEquals(first, second)
        assertNotEquals(first, token(dataToSign = byteArrayOf(9, 9, 9)))
    }

    @Test
    fun `distinguishes tokens differing in any single field`() {
        val base = token()

        assertNotEquals(base, token(id = "other-id"))
        assertNotEquals(base, token(format = FormatType.MSO_MDOC))
        assertNotEquals(base, token(holderKeyReference = "did:example:other"))
        assertNotEquals(base, token(signatureAlgorithm = "ES256"))
    }

    @Test
    fun `serializes dataToSign as base64url`() {
        val json = getObjectMapper().writeValueAsString(token(dataToSign = "hello".toByteArray()))

        assertTrue(json.contains("\"dataToSign\":\"${encoder.encodeToString("hello".toByteArray())}\""))
    }

    private fun token(
        id: String = "id-1",
        format: FormatType = FormatType.LDP_VC,
        holderKeyReference: String = "did:example:123",
        signatureAlgorithm: String = "Ed25519Signature2020",
        dataToSign: ByteArray = "dataToSign".toByteArray(Charsets.UTF_8)
    ) = UnsignedVPToken(id, format, holderKeyReference, signatureAlgorithm, dataToSign)
}
