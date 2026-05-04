package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import kotlin.test.*

class VPResponseMetadataTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(::validateField)

        every { validateField(any(), "String") } answers {
            val value = arg<String?>(0)
            value != null && value.isNotEmpty()
        }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create valid instance with jws and signatureAlgorithm`() {
        val result = LdpVPTokenSigningResult(
            jws = "valid-jws-value",
            signatureAlgorithm = "JsonWebSignature2020"
        )

        result.validate()
    }

    @Test
    fun `should throw exception when jws is empty for JWS-based algorithm`() {
        val result = LdpVPTokenSigningResult(
            jws = "",
            signatureAlgorithm = "JsonWebSignature2020"
        )

        assertFailsWith<InvalidInput> {
            result.validate()
        }
    }

    @Test
    fun `should throw exception when jws is null string for JWS-based algorithm`() {
        val result = LdpVPTokenSigningResult(
            jws = "null",
            signatureAlgorithm = "JsonWebSignature2020"
        )

        assertFailsWith<InvalidInput> {
            result.validate()
        }
    }

    @Test
    fun `should create valid instance with proofValue for Ed25519Signature2020`() {
        val result = LdpVPTokenSigningResult(
            proofValue = "valid-proof-value",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        result.validate()
    }

    @Test
    fun `should throw exception when proofValue is empty for Ed25519Signature2020`() {
        val result = LdpVPTokenSigningResult(
            proofValue = "",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        assertFailsWith<InvalidInput> {
            result.validate()
        }
    }

    @Test
    fun `should throw exception when proofValue is null string for Ed25519Signature2020`() {
        val result = LdpVPTokenSigningResult(
            proofValue = "null",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        assertFailsWith<InvalidInput> {
            result.validate()
        }
    }

    @Test
    fun `should create valid instance with jws for RSASignature2018`() {
        val result = LdpVPTokenSigningResult(
            jws = "valid-jws-value",
            signatureAlgorithm = "RSASignature2018"
        )

        result.validate()
    }

    @Test
    fun `should throw exception when jws is empty for RSASignature2018`() {
        val result = LdpVPTokenSigningResult(
            jws = "",
            signatureAlgorithm = "RSASignature2018"
        )

        assertFailsWith<InvalidInput> {
            result.validate()
        }
    }

    @Test
    fun `should create valid instance with jws for Ed25519Signature2018`() {
        val result = LdpVPTokenSigningResult(
            jws = "valid-jws-value",
            signatureAlgorithm = "Ed25519Signature2018"
        )

        result.validate()
    }
}
