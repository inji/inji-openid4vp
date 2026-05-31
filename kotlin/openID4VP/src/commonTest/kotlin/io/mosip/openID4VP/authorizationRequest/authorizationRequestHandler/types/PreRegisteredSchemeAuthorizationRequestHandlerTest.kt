package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.LdpVcFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.common.resolveJwksFromUri
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.testData.JWSUtil.Companion.buildTestJwk
import org.junit.jupiter.api.Test
import kotlin.test.*

class PreRegisteredSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletConfig: WalletConfig
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    private val validClientId = "mock-client"
    private var trustedVerifiers: MutableList<Verifier> = mutableListOf(
        Verifier(
            "mock-client", listOf(
                "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
            )
        ),
        Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback"),
            jwksUri = "https://example.com/.well-known/jwks.json",
            allowUnsignedRequest = false
        )
    )
    private val jwksUri = "https://example.com/.well-known/jwks.json"

    @BeforeTest
    fun setup() {

        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to validClientId,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
        )

        walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVcFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            trustedVerifiers = trustedVerifiers
        )

        mockkStatic("io.mosip.openID4VP.common.UtilsKt")
    }

    @Test
    fun `validateClientId should pass when client ID is trusted and validation is enabled`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            true,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should skip validation when shouldValidateClient is false`() {
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "untrusted-client-id",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            false,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should throw exception when client ID is not trusted`() {
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "untrusted-client-id",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            true,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateClientId()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `process should validate and return wallet metadata with requestObjectSigningAlgValuesSupported preserved`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            true,
            setResponseUri,
            walletNonce
        )

        val testMetadata = walletConfig.toWalletMetadata()
        val processedMetadata = handler.process(testMetadata)

        assertEquals(
            listOf(RequestSigningAlgorithm.EdDSA),
            processedMetadata.requestObjectSigningAlgValuesSupported
        )
    }


    @Test
    fun `validateAndParseRequestFields should pass for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            true,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should not throw exception when client metadata of the pre-registered verifier is not known and its available in authorization request`() {
        val trustedVerifiersWithoutClientMetadata: List<Verifier> = listOf(
            Verifier(
                "mock-client",
                listOf(
                    "https://mock-verifier.com/response-uri",
                    "https://verifier.env2.com/responseUri"
                ),
            )
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            (authorizationRequestParameters + mapOf(
                CLIENT_METADATA.value to clientMetadataString
            )) as MutableMap<String, Any>,
            WalletConfig(trustedVerifiers = trustedVerifiersWithoutClientMetadata),
            true,
            setResponseUri,
            walletNonce
        )

        assertDoesNotThrow {
            handler.validateAndParseRequestFields()
        }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response URI is not trusted`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            true,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateAndParseRequestFields should skip validation when shouldValidateClient is false`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            false,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `should extract key successfully when kid is present`() {
        val testKid = "test-key"
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(jwkList)

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, testKid)

        assertNotNull(publicKey)
        assertEquals("Ed25519", publicKey.algorithm)
        assertTrue(publicKey.encoded.isNotEmpty())
    }


    @Test
    fun `should throw when kid is present and not found in client metadata`() {
        val testKid = "some-other-key"
        val testJwk = buildTestJwk(kid = testKid)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(testJwk))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, "non-existent")
        }

        assertTrue(ex.message.contains("Public key extraction failed for kid"))
    }

    @Test
    fun `should throw error when no jwks_uri available in the trusted verifier`() {
        authorizationRequestParameters[CLIENT_ID.value] = "mock-client" // this client does not have jwks_uri as per trustedVerifiers

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "mock-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message.contains("Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request"))
    }

    @Test
    fun `should pick key by alg if no kid and one matching key present`() {
        val testJwk: Jwk = buildTestJwk(kid = null)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(testJwk))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        assertNotNull(publicKey)
    }

    @Test
    fun `should throw if multiple sig-use keys present and no kid`() {
        val key1 = buildTestJwk(kid = "k1")
        val key2 = buildTestJwk(kid = "k2")
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(key1, key2))


        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message.contains("Multiple ambiguous keys found for EdDSA with signature usage"))
    }

    @Test
    fun `should throw if no matching keys for alg`() {
        val key = buildTestJwk(kty = "RSA", crv = "") // non-EdDSA key
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(key))


        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message.contains("No public key found for algorithm: EdDSA with signature usage"))
    }

    @Test
    fun `should throw if curve is unsupported in matching key`() {
        val unsupportedCurveJWK = buildTestJwk(crv = "XYZ")
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(jwksUri, any()) } returns Jwks(listOf(unsupportedCurveJWK))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, "test-kid")
        }
        assertTrue(ex.message.contains("Public key extraction failed - Curve - XYZ is not supported. Supported: Ed25519"))
    }

    @Test
    fun `isRequestObjectSupported should return boolean value for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            true,
            setResponseUri,
            walletNonce
        )

        assertFalse(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should return false when shouldValidateClient is false`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            false,
            setResponseUri,
            walletNonce
        )
        assertTrue(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should throw when client id not in trusted verifiers`() {
        authorizationRequestParameters[CLIENT_ID.value] = "unknown-client"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "unknown-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            shouldValidateClient = true,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        val ex = assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
            handler.isUnsignedRequestSupported()
        }
        assertTrue(ex.message!!.contains("Verifier is not trusted by the wallet"))
    }

    @Test
    fun `isRequestObjectSupported should return false when verifier does not allow unsigned request`() {
        val verifier = Verifier(
            clientId = "test-client",
            jwksUri = jwksUri,
            allowUnsignedRequest = false,
            responseUris = listOf("https://example.com/response")
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters.apply { put(CLIENT_ID.value, "test-client") },
            walletConfig = WalletConfig(trustedVerifiers = listOf(verifier)),
            shouldValidateClient = true,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        assertFalse(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should return true when verifier allows unsigned request`() {
        val verifier = Verifier(
            clientId = "test-client",
            jwksUri = jwksUri,
            allowUnsignedRequest = true,
            responseUris = listOf("https://example.com/response")
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters.apply { put(CLIENT_ID.value, "test-client") },
            walletConfig = WalletConfig(trustedVerifiers = listOf(verifier)),
            shouldValidateClient = true,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        assertTrue(handler.isUnsignedRequestSupported())
    }
}
