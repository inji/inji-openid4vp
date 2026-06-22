package io.mosip.openID4VP.jwt.jwe.encryption

import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class EncryptionProviderTest {

    @Test
    fun `getEncrypter should create X25519Encrypter for OKP with X25519`() {
        val encrypter = EncryptionProvider.getEncrypter(baseOkpJwk())

        assertTrue(encrypter is X25519Encrypter)
    }

    @Test
    fun `getEncrypter should create ECDHEncrypter for supported EC curve`() {
        val encrypter = EncryptionProvider.getEncrypter(baseEcJwk())

        assertTrue(encrypter is ECDHEncrypter)
    }

    @Test
    fun `getEncrypter should throw JweEncryptionFailure for unsupported or missing algorithm`() {
        listOf("RSA-OAEP", null).forEach { alg ->
            val exception = assertFailsWith<OpenID4VPExceptions.JweEncryptionFailure> {
                EncryptionProvider.getEncrypter(baseOkpJwk(alg = alg))
            }

            assertOpenId4VPException(
                exception,
                expectedMessage = "Unsupported JWE algorithm: $alg",
                expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
            )
        }
    }

    @Test
    fun `getEncrypter should throw JweEncryptionFailure for OKP with non-X25519 curve`() {
        val exception = assertFailsWith<OpenID4VPExceptions.JweEncryptionFailure> {
            EncryptionProvider.getEncrypter(baseOkpJwk(crv = "Ed25519"))
        }

        assertOpenId4VPException(
            exception,
            expectedMessage = "Unsupported OKP curve for ECDH-ES: Ed25519. Only X25519 is supported.",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `getEncrypter should throw JweEncryptionFailure for EC with unsupported curve`() {
        val exception = assertFailsWith<OpenID4VPExceptions.JweEncryptionFailure> {
            EncryptionProvider.getEncrypter(baseEcJwk(crv = "secp256k1"))
        }

        // Current implementation populates class name as the exception message in this branch.
        assertOpenId4VPException(
            exception,
            expectedMessage = "EncryptionProvider",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `getEncrypter should throw UnsupportedKeyExchangeAlgorithm for unsupported key type`() {
        val exception = assertFailsWith<OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm> {
            EncryptionProvider.getEncrypter(baseOkpJwk(kty = "RSA"))
        }

        assertOpenId4VPException(
            exception,
            expectedMessage = "Required Key exchange algorithm is not supported",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `getEncrypter should throw UnsupportedKeyExchangeAlgorithm for EC key without y coordinate`() {
        val exception = assertFailsWith<OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm> {
            EncryptionProvider.getEncrypter(baseEcJwk(y = null))
        }

        assertOpenId4VPException(
            exception,
            expectedMessage = "Required Key exchange algorithm is not supported",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    private fun baseOkpJwk(
        alg: String? = "ECDH-ES",
        kty: String = "OKP",
        crv: String? = "X25519"
    ): Jwk = Jwk(
        alg = alg,
        kty = kty,
        use = "enc",
        crv = crv,
        x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        kid = "okp-key-1"
    )

    private fun baseEcJwk(
        alg: String? = "ECDH-ES",
        kty: String = "EC",
        crv: String? = "P-256",
        y: String? = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    ): Jwk = Jwk(
        alg = alg,
        kty = kty,
        use = "enc",
        crv = crv,
        x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        y = y,
        kid = "ec-key-1"
    )
}
