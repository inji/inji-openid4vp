package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class VPTokenSigningResultTest {

    private val sampleId = "test-uuid-123"
    private val sampleSignedData = "signature-bytes".toByteArray()

    @Test
    fun `should create VPTokenSigningResult with correct id and signedData`() {
        val result = VPTokenSigningResult(id = sampleId, signedData = sampleSignedData)

        assertEquals(sampleId, result.id)
        assertTrue(sampleSignedData.contentEquals(result.signedData))
    }

    @Test
    fun `equals should return false when id differs`() {
        val result1 = VPTokenSigningResult(id = sampleId, signedData = "sig-a".toByteArray())
        val result2 = VPTokenSigningResult(id = "different-id", signedData = "sig-a".toByteArray())

        assertNotEquals(result1, result2)
    }
}
