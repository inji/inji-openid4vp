package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.MissingInput
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class VPTokenUtilsTest {

    @Test
    fun `getUnsignedVPToken should return token for matching identifier`() {
        val token = UnsignedVPToken(
            id = "token-1",
            format = FormatType.VC_SD_JWT,
            holderKeyReference = "kid-token-1",
            signatureAlgorithm = "ES256K",
            dataToSign = "unsigned-data-1".toByteArray()
        )

        val result = getUnsignedVPToken(
            unsignedVPTokens = listOf(token),
            identifier = "token-1",
            className = "VPTokenUtilsTest"
        )

        assertEquals("token-1", result.id)
        assertEquals(FormatType.VC_SD_JWT, result.format)
        assertEquals("kid-token-1", result.holderKeyReference)
    }

    @Test
    fun `getUnsignedVPToken should throw InvalidData for missing identifier`() {
        val token = UnsignedVPToken(
            id = "token-1",
            format = FormatType.VC_SD_JWT,
            holderKeyReference = "kid-token-1",
            signatureAlgorithm = "ES256K",
            dataToSign = "unsigned-data-1".toByteArray()
        )

        val exception = assertFailsWith<InvalidData> {
            getUnsignedVPToken(
                unsignedVPTokens = listOf(token),
                identifier = "missing-token",
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Missing unsigned VP token for identifier missing-token",
            exception.message
        )
    }

    @Test
    fun `getUnsignedVPToken should throw InvalidData for duplicate identifier`() {
        val duplicateTokens = listOf(
            UnsignedVPToken(
                id = "dup-token",
                format = FormatType.VC_SD_JWT,
                holderKeyReference = "kid-1",
                signatureAlgorithm = "ES256K",
                dataToSign = "unsigned-data-1".toByteArray()
            ),
            UnsignedVPToken(
                id = "dup-token",
                format = FormatType.VC_SD_JWT,
                holderKeyReference = "kid-2",
                signatureAlgorithm = "ES256K",
                dataToSign = "unsigned-data-2".toByteArray()
            )
        )

        val exception = assertFailsWith<InvalidData> {
            getUnsignedVPToken(
                unsignedVPTokens = duplicateTokens,
                identifier = "dup-token",
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Duplicate unsigned VP token for identifier dup-token",
            exception.message
        )
    }

    @Test
    fun `getVPTokenSigningResult should throw InvalidData for duplicate identifier`() {
        val signingResults = listOf(
            VPTokenSigningResult(id = "dup-id", signedData = "sig-1".toByteArray()),
            VPTokenSigningResult(id = "dup-id", signedData = "sig-2".toByteArray())
        )

        val exception = assertFailsWith<InvalidData> {
            getVPTokenSigningResult(
                vpTokenSigningResults = signingResults,
                identifier = "dup-id",
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Duplicate VP token signing result for credential identifier dup-id",
            exception.message
        )
    }

    @Test
    fun `getVPTokenSigningResult should throw MissingInput for unknown identifier`() {
        val signingResults = listOf(
            VPTokenSigningResult(id = "known-id", signedData = "sig-1".toByteArray())
        )

        val exception = assertFailsWith<MissingInput> {
            getVPTokenSigningResult(
                vpTokenSigningResults = signingResults,
                identifier = "unknown-id",
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Missing VP token signing result for credential identifier unknown-id",
            exception.message
        )
    }
}

