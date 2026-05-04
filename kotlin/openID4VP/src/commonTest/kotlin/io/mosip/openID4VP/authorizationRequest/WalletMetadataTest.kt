package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.*

class WalletMetadataTest {

    @Test
    fun `should create WalletMetadata with primary constructor`() {
        val walletMetadata = WalletMetadata(
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to LdpVcFormatSupported(
                    proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                )
            ),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(ContentEncryptionAlgorithm.A256GCM),
            responseTypeSupported = listOf(ResponseType.VP_TOKEN)
        )

        assertEquals(1, walletMetadata.vpFormatsSupported?.size)
        assertEquals(listOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER), walletMetadata.clientIdPrefixesSupported)
        assertEquals(listOf(RequestSigningAlgorithm.EdDSA), walletMetadata.requestObjectSigningAlgValuesSupported)
        assertEquals(listOf(KeyManagementAlgorithm.ECDH_ES), walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertEquals(listOf(ContentEncryptionAlgorithm.A256GCM), walletMetadata.authorizationEncryptionEncValuesSupported)
        assertEquals(listOf(ResponseType.VP_TOKEN), walletMetadata.responseTypeSupported)
    }

    @Test
    fun `should create WalletMetadata with default constructor`() {
        val walletMetadata = WalletMetadata()

        assertNotNull(walletMetadata.vpFormatsSupported)
        assertNotNull(walletMetadata.clientIdPrefixesSupported)
        assertNotNull(walletMetadata.requestObjectSigningAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionEncValuesSupported)
        assertNotNull(walletMetadata.responseTypeSupported)
    }

    @Test
    fun `should create WalletMetadata with deprecated constructor`() {
        val walletMetadata = WalletMetadata(
            vpFormatsSupported = mapOf(
                "LDP_VC" to LdpVcFormatSupported(
                    proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                )
            ),
            clientIdPrefixesSupported = listOf("PRE_REGISTERED"),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH_ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )

        assertEquals(1, walletMetadata.vpFormatsSupported?.size)
        assertEquals(listOf(ClientIdPrefix.PRE_REGISTERED), walletMetadata.clientIdPrefixesSupported)
        assertEquals(listOf(RequestSigningAlgorithm.EdDSA), walletMetadata.requestObjectSigningAlgValuesSupported)
        assertEquals(listOf(KeyManagementAlgorithm.ECDH_ES), walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertEquals(listOf(ContentEncryptionAlgorithm.A256GCM), walletMetadata.authorizationEncryptionEncValuesSupported)
    }

    @Test
    fun `should throw exception for invalid enum values in deprecated constructor`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                vpFormatsSupported = mapOf(
                    "INVALID_FORMAT" to LdpVcFormatSupported(
                        proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                    )
                )
            )
        }

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                vpFormatsSupported = mapOf(
                    "LDP_VC" to LdpVcFormatSupported(
                        proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                    )
                ),
                clientIdPrefixesSupported = listOf("INVALID_SCHEME")
            )
        }

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                vpFormatsSupported = mapOf(
                    "LDP_VC" to LdpVcFormatSupported(
                        proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                    )
                ),
                requestObjectSigningAlgValuesSupported = listOf("INVALID_ALG")
            )
        }
    }

    @Test
    fun `should parse enum values correctly`() {
        assertEquals(
            VPFormatType.LDP_VC,
            WalletMetadata.parseEnum("LDP_VC", VPFormatType.entries.toTypedArray(), "VPFormatType")
        )

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata.parseEnum("INVALID", VPFormatType.entries.toTypedArray(), "VPFormatType")
        }
    }

    @Test
    fun `should create VPFormatSupported with null values`() {
        val vpFormatSupported = LdpVcFormatSupported(null)
        assertNull(vpFormatSupported.toAlgValuesSupported())
    }

    @Test
    fun `should handle null values in WalletMetadata constructor`() {
        val walletMetadata = WalletMetadata(
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to LdpVcFormatSupported(
                    proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                )
            ),
            clientIdPrefixesSupported = null,
            requestObjectSigningAlgValuesSupported = null,
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = null,
            responseTypeSupported = null
        )

        assertNotNull(walletMetadata.vpFormatsSupported)
        assertNotNull(walletMetadata.clientIdPrefixesSupported)
        assertNotNull(walletMetadata.requestObjectSigningAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionEncValuesSupported)
        assertNotNull(walletMetadata.responseTypeSupported)
    }
}