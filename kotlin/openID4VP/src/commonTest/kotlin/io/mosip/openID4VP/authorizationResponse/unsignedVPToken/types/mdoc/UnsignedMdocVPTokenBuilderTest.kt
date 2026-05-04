package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
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
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.*

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
        firstDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType1"))
        }
        secondDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType2"))
        }
    }


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create token with empty device auth when credentialInputDescriptorMappings list is empty`() {
        val result = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce
        ).build(emptyList())

        val unsignedToken = result.second
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.isEmpty())
        // Verify payload is null
        assertNull(result.first)
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
        ).build(mappings)
        val unsignedToken = result.second
        assertEquals(2, unsignedToken.docTypeToDeviceAuthenticationBytes.size)
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.containsKey("docType1"))
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.containsKey("docType2"))
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
                mdocGeneratedNonce = walletNonce
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
            mdocGeneratedNonce = walletNonce
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
            mdocGeneratedNonce = walletNonce
        ).build(mappings)
        assertEquals("docType1", mappings[0].identifier)
        assertEquals("docType2", mappings[1].identifier)
    }
}
