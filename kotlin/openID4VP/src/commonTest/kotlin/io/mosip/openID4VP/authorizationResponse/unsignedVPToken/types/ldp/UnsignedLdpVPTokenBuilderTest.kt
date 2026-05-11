package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.LdpKeyResolver
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.presentationDefinitionMap
import kotlin.test.*

class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"
    private val challenge = "test-challenge"
    private val domain = "test-domain.com"
    private val mockDateTime = "2023-01-01T12:00:00Z"
    private val mockCanonicalizedData = "canonicalized-data"

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(presentationDefinitionMap, PresentationDefinitionSerializer),
        responseUri = "https://mock-verifier.com/response",
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
    )

    @BeforeTest
    fun setup() {
        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns mockDateTime

        mockkObject(URDNA2015Canonicalization)
        every { URDNA2015Canonicalization.canonicalize(any()) } returns mockCanonicalizedData

        mockkObject(LdpKeyResolver)
        every { LdpKeyResolver.resolveJWSAlgorithm(any()) } returns "EdDSA"

        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            val input = firstArg<String>()
            java.util.Base64.getUrlDecoder().decode(input)
        }

        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            val input = firstArg<ByteArray>()
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(input)
        }
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with Ed25519Signature2020`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            holder = holder,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
        val (payload, unsignedTokens) = builder.build(mappings)
        val vpPayload = payload as LdpVPToken
        assertEquals(2, vpPayload.context.size)
        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        assertTrue(vpPayload.context.contains("https://w3id.org/security/suites/ed25519-2020/v1"))
        assertEquals(listOf("VerifiablePresentation"), vpPayload.type)
        assertEquals(listOf(ldpCredential1, ldpCredential2), vpPayload.verifiableCredential)
        assertEquals(id, vpPayload.id)
        assertEquals(holder, vpPayload.holder)
        val proof = vpPayload.proof
        assertNotNull(proof)
        assertEquals(SignatureSuiteAlgorithm.Ed25519Signature2020.value, proof?.type)
        assertEquals(mockDateTime, proof?.created)
        assertEquals(holder, proof?.verificationMethod)
        assertEquals(domain, proof?.domain)
        assertEquals(challenge, proof?.challenge)
        assertEquals(1, unsignedTokens.size)
        assertContentEquals(java.util.Base64.getUrlDecoder().decode(mockCanonicalizedData), unsignedTokens.first().dataToSign)
        assertEquals(FormatType.LDP_VC, unsignedTokens.first().format)
        assertEquals(holder, unsignedTokens.first().holderKeyReference)
        assertEquals("EdDSA", unsignedTokens.first().signatureAlgorithm)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with JsonWebSignature2020`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            holder = holder,
            signatureSuite = SignatureSuiteAlgorithm.JsonWebSignature2020.value
        )
        val (payload, unsignedToken) = builder.build(mappings)
        val vpPayload = payload as LdpVPToken
        assertEquals(2, vpPayload.context.size)
        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        assertTrue(vpPayload.context.contains("https://w3id.org/security/suites/jws-2020/v1"))
        val proof = vpPayload.proof
        assertNotNull(proof)
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value, proof?.type)
        assertEquals(1, unsignedToken.size)
        assertEquals("EdDSA", unsignedToken.first().signatureAlgorithm)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with unknown signature suite`() {
        val unknownSignatureSuite = "UnknownSignatureSuite"
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            holder = holder,
            signatureSuite = unknownSignatureSuite
        )
        val (payload, unsignedToken) = builder.build(mappings)
        val vpPayload = payload as LdpVPToken
        assertEquals(1, vpPayload.context.size)
        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        val proof = vpPayload.proof
        assertNotNull(proof)
        assertEquals(unknownSignatureSuite, proof?.type)
        assertEquals(listOf(ldpCredential1, ldpCredential2), vpPayload.verifiableCredential)
        assertEquals(1, unsignedToken.size)
        assertEquals("EdDSA", unsignedToken.first().signatureAlgorithm)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) canonicalization error handling`() {
        every { URDNA2015Canonicalization.canonicalize(any()) } throws RuntimeException("Canonicalization failed")
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            holder = holder,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
        val exception = assertFailsWith<RuntimeException> {
            builder.build(mappings)
        }
        assertEquals("Canonicalization failed", exception.message)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) sets nestedPath correctly`() {
        val credentialInputDescriptorMappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            holder = holder,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )

        builder.build(credentialInputDescriptorMappings)

        assertEquals("$.verifiableCredential[0]", credentialInputDescriptorMappings[0].nestedPath)
        assertEquals("$.verifiableCredential[1]", credentialInputDescriptorMappings[1].nestedPath)
    }
}
