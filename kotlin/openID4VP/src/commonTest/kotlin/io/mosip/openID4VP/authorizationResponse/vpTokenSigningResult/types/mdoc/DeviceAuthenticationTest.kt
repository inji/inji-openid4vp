package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mockk.clearAllMocks
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import kotlin.test.*

class DeviceAuthenticationTest {


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `validate succeeds with valid inputs`() {
        val deviceAuth = DeviceAuthentication("testSignature".toByteArray(), "SHA256withRSA")
        deviceAuth.validate() // Should not throw
    }

    @Test
    fun `validate throws exception with empty signature`() {
        val deviceAuth = DeviceAuthentication(ByteArray(0), "SHA256withRSA")

        val exception = assertFailsWith<InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals(
            "Invalid Input: mdoc_vp_token_signing_result->device_authentication->signature value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `validate throws exception with null algorithm string`() {
        val deviceAuth = DeviceAuthentication("testSignature".toByteArray(), "null")

        val exception = assertFailsWith<InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals(
            "Invalid Input: mdoc_vp_token_signing_result->device_authentication->algorithm value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `validate throws exception with blank algorithm`() {
        val deviceAuth = DeviceAuthentication("testSignature".toByteArray(), "")

        assertFailsWith<InvalidInput> {
            deviceAuth.validate()
        }
    }

    @Test
    fun `compares the signature by content`() {
        val first = DeviceAuthentication(byteArrayOf(1, 2, 3), "ES256")
        val second = DeviceAuthentication(byteArrayOf(1, 2, 3), "ES256")

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertTrue(first == first)
        assertFalse(first.equals("not-a-device-authentication"))
        assertNotEquals(first, DeviceAuthentication(byteArrayOf(9), "ES256"))
        assertNotEquals(first, DeviceAuthentication(byteArrayOf(1, 2, 3), "EdDSA"))
    }
}
