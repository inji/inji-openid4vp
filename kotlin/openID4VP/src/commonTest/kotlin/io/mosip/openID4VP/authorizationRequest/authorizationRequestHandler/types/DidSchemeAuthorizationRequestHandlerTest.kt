package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ProofType
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.assertWalletConfigAndMetadata
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.didUrl
import io.mosip.openID4VP.testData.jws
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import org.junit.jupiter.api.Test
import java.security.PublicKey
import kotlin.test.*

class DidSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletConfig: WalletConfig
    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @BeforeTest
    fun setup() {
        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to didUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString
        )

        walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported(proofTypeValues = listOf(ProofType.Ed25519Signature2020))),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )

        mockkObject(JWSHandler)
        every { JWSHandler.extractDataJsonFromJws(jws,JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "ES256")
        every { JWSHandler.extractDataJsonFromJws(jws,JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestParameters
    }

    @Test
    fun `process should return wallet metadata when requestObjectSigningAlgValuesSupported is valid`() {
        val handler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
            clientId = didUrl,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val result = handler.getWalletMetadata(walletConfig)

        assertWalletConfigAndMetadata(walletConfig, result)
    }

    @Test
    fun `process should throw exception when requestObjectSigningAlgValuesSupported is empty`() {
        val handler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
            clientId = didUrl,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val invalidWalletConfig =
            walletConfig.copy(requestObjectSigningAlgValuesSupported = emptyList())

        val exception = assertFailsWith<Exception> {
            handler.getWalletMetadata(invalidWalletConfig)
        }
        assertTrue(exception.message?.contains("request_object_signing_alg_values_supported is not present") == true)
    }

    @Test
    fun `extractPublicKey should call DidPublicKeyResolver with correct values`() {
        val testKid = "test-key"

        val resolver = mockk<DidPublicKeyResolver>()
        val mockPublicKey = mockk<PublicKey>()
        every { resolver.resolve(didUrl, testKid) } returns mockPublicKey

        mockkConstructor(DidPublicKeyResolver::class)
        every { anyConstructed<DidPublicKeyResolver>().resolve(any(), any()) } answers {
            resolver.resolve(firstArg(), secondArg())
        }

        val handler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
            clientId = didUrl,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(SignatureAlgorithm.EdDSA, testKid)

        assertEquals(mockPublicKey, publicKey)
        verify { resolver.resolve(didUrl, testKid) }

        unmockkConstructor(DidPublicKeyResolver::class)
    }

    // ── validateClientAuthenticity tests ──────────────────────────────────────

    private val didDocumentUrl =
        "https://mosip.github.io/inji-mock-services/openid4vp-service/docs/did.json"

    private fun didDocumentJson(serviceEndpoint: String) =
        """{"service":[{"id":"#openid4vp","type":"OpenID4VPService","serviceEndpoint":"$serviceEndpoint"}]}"""

    private fun buildHandler(
        clientId: String = didUrl,
        params: MutableMap<String, Any> = authorizationRequestParameters
    ) = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
        clientId = clientId,
        specVersion = SpecVersion.DRAFT_23,
        authorizationRequestParameters = params,
        walletConfig = walletConfig,
        setResponseDispatchInfo = setResponseDispatchInfo,
        walletNonce = walletNonce
    )

    @Test
    fun `validateClientAuthenticity passes when response_uri matches a DID document service endpoint`() {
        mockkObject(NetworkManagerClient)
        every {
            NetworkManagerClient.sendHTTPRequest(didDocumentUrl, HttpMethod.GET, null, null)
        } returns NetworkResponse(200, didDocumentJson("https://example.com/response"), emptyMap())

        // authorizationRequestParameters already has response_uri = "https://example.com/response"
        buildHandler().validateClientAuthenticity()

        unmockkObject(NetworkManagerClient)
    }

    @Test
    fun `validateClientAuthenticity throws when response_uri is not a service endpoint of the DID`() {
        mockkObject(NetworkManagerClient)
        every {
            NetworkManagerClient.sendHTTPRequest(didDocumentUrl, HttpMethod.GET, null, null)
        } returns NetworkResponse(200, didDocumentJson("https://legitimate.com/response"), emptyMap())

        val params = authorizationRequestParameters.toMutableMap().apply {
            put(RESPONSE_URI.value, "https://attacker.com/bad")
        }

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            buildHandler(params = params).validateClientAuthenticity()
        }
        assertTrue(exception.message.contains("is not a service endpoint"))

        unmockkObject(NetworkManagerClient)
    }

    @Test
    fun `validateClientAuthenticity returns early when response_uri is absent`() {
        val paramsWithoutResponseUri = authorizationRequestParameters.toMutableMap().apply {
            remove(RESPONSE_URI.value)
        }

        // No network mock needed — method must return early before fetching DID document
        buildHandler(params = paramsWithoutResponseUri).validateClientAuthenticity()
    }

    @Test
    fun `validateClientAuthenticity skips validation for non-web DID methods`() {
        val params = authorizationRequestParameters.toMutableMap().apply {
            put(RESPONSE_URI.value, "https://any.com/response")
        }

        // did:key has no service endpoints — no HTTP call should be made
        buildHandler(clientId = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", params = params)
            .validateClientAuthenticity()
    }

    @Test
    fun `validateClientAuthenticity resolves correct URL for did:web with percent-encoded port`() {
        val didWithPort = "did:web:localhost%3A8080"
        val expectedUrl = "https://localhost:8080/.well-known/did.json"
        val params = authorizationRequestParameters.toMutableMap().apply {
            put(RESPONSE_URI.value, "https://localhost:8080/response")
        }

        mockkObject(NetworkManagerClient)
        every {
            NetworkManagerClient.sendHTTPRequest(expectedUrl, HttpMethod.GET, null, null)
        } returns NetworkResponse(200, didDocumentJson("https://localhost:8080/response"), emptyMap())

        buildHandler(clientId = didWithPort, params = params).validateClientAuthenticity()

        verify { NetworkManagerClient.sendHTTPRequest(expectedUrl, HttpMethod.GET, null, null) }
        unmockkObject(NetworkManagerClient)
    }

    @Test
    fun `validateClientAuthenticity throws when DID document has no service endpoints`() {
        mockkObject(NetworkManagerClient)
        every {
            NetworkManagerClient.sendHTTPRequest(didDocumentUrl, HttpMethod.GET, null, null)
        } returns NetworkResponse(200, """{}""", emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            buildHandler().validateClientAuthenticity()
        }
        assertTrue(exception.message.contains("is not a service endpoint"))

        unmockkObject(NetworkManagerClient)
    }

    @Test
    fun `validateClientAuthenticity throws when DID document fetch returns non-2xx`() {
        mockkObject(NetworkManagerClient)
        every {
            NetworkManagerClient.sendHTTPRequest(didDocumentUrl, HttpMethod.GET, null, null)
        } returns NetworkResponse(404, "", emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            buildHandler().validateClientAuthenticity()
        }
        assertTrue(exception.message.contains("Failed to resolve DID document"))

        unmockkObject(NetworkManagerClient)
    }

    @Test
    fun `confirmSpecVersionIdentifiedFromRequest validates did and decentralized_identifier prefixes`() {
        val didHandler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
            clientId = "did:web:example.com",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        assertTrue(didHandler.confirmSpecVersionIdentifiedFromRequest())

        val decentralizedIdentifierHandler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
            clientId = "${ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value}:did:web:example.com",
            specVersion = SpecVersion.V1,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        assertTrue(decentralizedIdentifierHandler.confirmSpecVersionIdentifiedFromRequest())

        val mismatchingHandler = DecentralizedIdentifierPrefixAuthorizationRequestHandler(
            clientId = "did:web:example.com",
            specVersion = SpecVersion.V1,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        assertFalse(mismatchingHandler.confirmSpecVersionIdentifiedFromRequest())
    }

}
