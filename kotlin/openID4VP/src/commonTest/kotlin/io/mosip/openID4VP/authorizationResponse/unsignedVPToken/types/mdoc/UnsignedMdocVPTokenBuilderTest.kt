package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.resolveMdocKeyAndAlg
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletConfig
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.*
import co.nstant.`in`.cbor.model.Map as CborMap
import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.common.hexToByteArray
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class UnsignedMdocVPTokenBuilderTest {
    private val secondMdocCredential = "second_mdoc_credential"
    private lateinit var firstDecodedMap: Map
    private lateinit var secondDecodedMap: Map

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(presentationDefinitionMap, PresentationDefinitionSerializer),
        responseUri = responseUrl,
        redirectUri = null,
        nonce = verifierNonce,
        state = null,
        walletNonce = null,
    )

    @BeforeTest
    fun setUp() {
        mockkStatic(::getDecodedMdocCredential)
        mockkStatic(::resolveMdocKeyAndAlg)
        every { resolveMdocKeyAndAlg(any(), any()) } returns Pair("keyRef", "ES256")
        firstDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType1"))
        }
        secondDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType2"))
        }
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should create token with empty device auth when credentialInputDescriptorMappings list is empty`() {
        val result = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(emptyList())

        val unsignedTokens = result.second
        val payloadMap = result.first as? kotlin.collections.Map<*, *>
        assertNotNull(payloadMap)
        assertTrue(payloadMap.isEmpty())
        assertTrue(unsignedTokens.isEmpty())
    }

    @Test
    fun `should handle multiple different mdoc credentials correctly with credentialInputDescriptorMappings`() {
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                mdocCredential,
                "input-descriptor-id1"
            ),
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                secondMdocCredential,
                "input-descriptor-id2"
            )
        )
        val result = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce
        ,
            walletConfig
        ).build(mappings)
        val unsignedTokens = result.second
        @Suppress("UNCHECKED_CAST")
        val payloadMap = result.first as? kotlin.collections.Map<String, String>
        assertNotNull(payloadMap)
        assertEquals(2, payloadMap.size)
        assertEquals(2, unsignedTokens.size)

        val identifiers = mappings.map { mapping ->
            requireNotNull(mapping.identifier) { "identifier should be set for each mapping" }
        }
        assertTrue(identifiers.all { it.isNotBlank() })
        assertEquals(identifiers.toSet(), payloadMap.keys)
        assertEquals(identifiers, unsignedTokens.map { it.id })

        identifiers.forEachIndexed { index, identifier ->
            assertContentEquals(
                io.mosip.openID4VP.common.hexToByteArray(payloadMap[identifier]!!),
                unsignedTokens[index].dataToSign
            )
        }
        assertEquals(listOf("keyRef", "keyRef"), unsignedTokens.map { it.holderKeyReference })
        assertEquals(listOf("ES256", "ES256"), unsignedTokens.map { it.signatureAlgorithm })
    }

    @Test
    fun `should throw exception for malformed mdoc credential with credentialInputDescriptorMappings`() {
        mockkStatic(::getDecodedMdocCredential)
        every { getDecodedMdocCredential(any()) } throws IllegalArgumentException("Invalid CBOR data")
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                "invalid_mdoc_credential",
                "input-descriptor-id1"
            )
        )
        val exception = assertFailsWith<IllegalArgumentException> {
            UnsignedMdocVPTokenBuilder(
                authorizationRequest = testAuthorizationRequest,
                specVersion = SpecVersion.DRAFT_23,
                responseUri = responseUrl,
                mdocGeneratedNonce = walletNonce,
                walletConfig
            ).build(mappings)
        }
        assertEquals("Invalid CBOR data", exception.message)
    }

    @Test
    fun `should set nestedPath correctly in credentialInputDescriptorMappings`() {
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                mdocCredential,
                "input-descriptor-id1"
            ),
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                secondMdocCredential,
                "input-descriptor-id2"
            )
        )
        UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(mappings)
        assertNull(mappings[0].nestedPath)
        assertNull(mappings[1].nestedPath)
    }

    @Test
    fun `should set identifier correctly in credentialInputDescriptorMappings`() {
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                mdocCredential,
                "input-descriptor-id1"
            ),
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                secondMdocCredential,
                "input-descriptor-id2"
            ),
        )
        UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(mappings)
        assertTrue(!mappings[0].identifier.isNullOrBlank())
        assertTrue(!mappings[1].identifier.isNullOrBlank())
        assertNotEquals(mappings[0].identifier, mappings[1].identifier)
    }

    @Test
    fun `builds unsigned tokens for dcql mappings under draft 23`() {
        val mappings = mutableListOf(
            dcqlMapping(mdocCredential, "mobile-id"),
            dcqlMapping(secondMdocCredential, "residence-id")
        )

        val (payload, tokens) = builder(SpecVersion.DRAFT_23, dcqlRequest("direct_post"))
            .build(mappings)

        assertEquals(2, payload.size)
        assertEquals(2, tokens.size)
        val identifiers = mappings.map { requireNotNull(it.identifier) }
        assertEquals(identifiers.toSet(), payload.keys)
        assertEquals(identifiers, tokens.map { it.id })
        assertNotEquals(identifiers[0], identifiers[1])
        tokens.forEach {
            assertEquals(FormatType.MSO_MDOC, it.format)
            assertEquals("keyRef", it.holderKeyReference)
            assertEquals("ES256", it.signatureAlgorithm)
        }
        identifiers.forEachIndexed { index, identifier ->
            assertContentEquals(hexToByteArray(payload.getValue(identifier)), tokens[index].dataToSign)
        }
    }

    @Test
    fun `builds unsigned tokens for dcql mappings under spec V1`() {
        val mappings = mutableListOf(dcqlMapping(mdocCredential, "mobile-id"))

        val (payload, tokens) = builder(SpecVersion.V1, dcqlRequest("direct_post")).build(mappings)

        assertEquals(1, tokens.size)
        assertTrue(payload.values.single().isNotEmpty())
    }

    @Test
    fun `spec V1 handover incorporates the verifier encryption key thumbprint`() {
        val mappings = mutableListOf(dcqlMapping(mdocCredential, "mobile-id"))
        val encrypted = builder(
            SpecVersion.V1,
            dcqlRequest("direct_post.jwt", clientMetadata = clientMetadataWithEncKey())
        ).build(mappings)

        val plainMappings = mutableListOf(dcqlMapping(mdocCredential, "mobile-id"))
        val plain = builder(SpecVersion.V1, dcqlRequest("direct_post")).build(plainMappings)

        assertNotEquals(
            plain.first.values.single(),
            encrypted.first.values.single()
        )
    }

    @Test
    fun `spec V1 handover differs from the draft 23 handover`() {
        val v1 = builder(SpecVersion.V1, dcqlRequest("direct_post"))
            .build(mutableListOf(dcqlMapping(mdocCredential, "mobile-id")))
        val draft23 = builder(SpecVersion.DRAFT_23, dcqlRequest("direct_post"))
            .build(mutableListOf(dcqlMapping(mdocCredential, "mobile-id")))

        assertNotEquals(v1.first.values.single(), draft23.first.values.single())
    }

    @Test
    fun `spec V1 rejects an unsupported response mode`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder(SpecVersion.V1, dcqlRequest("unsupported_mode"))
                .build(mutableListOf(dcqlMapping(mdocCredential, "mobile-id")))
        }
        assertEquals("Given response_mode is not supported", exception.message)
    }

    @Test
    fun `returns empty results for an empty dcql mapping list`() {
        val (payload, tokens) = builder(SpecVersion.DRAFT_23, dcqlRequest("direct_post"))
            .build(mutableListOf<CredentialToCredentialQueryIdMapping>())

        assertTrue(payload.isEmpty())
        assertTrue(tokens.isEmpty())
    }

    @Test
    fun `rejects duplicate doctypes across dcql mappings`() {
        val mappings = mutableListOf(
            dcqlMapping(mdocCredential, "mobile-id"),
            dcqlMapping(mdocCredential, "other-id")
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder(SpecVersion.DRAFT_23, dcqlRequest("direct_post")).build(mappings)
        }
        assertEquals("Duplicate Mdoc Credentials with same doctype found", exception.message)
    }

    @Test
    fun `rejects a dcql mdoc credential that is not a string`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(FormatType.MSO_MDOC, mapOf("a" to "b"), "mobile-id")
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder(SpecVersion.DRAFT_23, dcqlRequest("direct_post")).build(mappings)
        }
        assertEquals("MDOC credential is not a String", exception.message)
    }

    private fun docTypeMap(docType: String) = CborMap().apply {
        put(UnicodeString("docType"), UnicodeString(docType))
    }

    private fun dcqlMapping(credential: Any, credentialQueryId: String) =
        CredentialToCredentialQueryIdMapping(FormatType.MSO_MDOC, credential, credentialQueryId)

    private fun clientMetadataWithEncKey() = ClientMetadata(
        vpFormatsSupported = mapOf("mso_mdoc" to io.mosip.openID4VP.authorizationRequest.MsoMdocVpFormatSupported()),
        encryptedResponseEncValuesSupported = listOf("A256GCM"),
        jwks = Jwks(
            keys = listOf(
                Jwk(
                    kty = "OKP",
                    crv = "X25519",
                    use = "enc",
                    x = "BVFxIytOMlSBiJRIMdxU_UnJhqEUlpBJ4jcm8pMBGXo",
                    alg = "ECDH-ES",
                    kid = "key-1"
                )
            )
        )
    )

    private fun dcqlRequest(
        responseMode: String,
        clientMetadata: ClientMetadata? = null
    ) = AuthorizationDcqlRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = responseMode,
        responseUri = responseUrl,
        redirectUri = null,
        nonce = verifierNonce,
        walletNonce = null,
        state = null,
        clientMetadata = clientMetadata,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value)
            )
        )
    )

    private fun builder(specVersion: SpecVersion, request: AuthorizationDcqlRequest) =
        UnsignedMdocVPTokenBuilder(
            authorizationRequest = request,
            specVersion = specVersion,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig = walletConfig
        )
}
