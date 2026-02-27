package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.ldpCredentialWithDataModel2
import org.junit.Test
import kotlin.test.*

class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"
    private val challenge = "test-challenge"
    private val domain = "test-domain.com"
    private val mockDateTime = "2023-01-01T12:00:00Z"
    private val mockCanonicalizedData = "canonicalized-data"

    @BeforeTest
    fun setup() {
        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns mockDateTime

        mockkObject(URDNA2015Canonicalization)
        every { URDNA2015Canonicalization.canonicalize(any()) } returns mockCanonicalizedData
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
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
        val (payload, unsignedToken) = builder.build(mappings)
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
        assertEquals(mockCanonicalizedData, (unsignedToken as UnsignedLdpVPToken).dataToSign)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with JsonWebSignature2020`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
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
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with unknown signature suite`() {
        val unknownSignatureSuite = "UnknownSignatureSuite"
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = unknownSignatureSuite
        )
        val (payload, _) = builder.build(mappings)
        val vpPayload = payload as LdpVPToken
        assertEquals(1, vpPayload.context.size)
        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        val proof = vpPayload.proof
        assertNotNull(proof)
        assertEquals(unknownSignatureSuite, proof?.type)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) canonicalization error handling`() {
        every { URDNA2015Canonicalization.canonicalize(any()) } throws RuntimeException("Canonicalization failed")
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, "input-descriptor-id2")
        )
        val builder = UnsignedLdpVPTokenBuilder(
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
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
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )

        builder.build(credentialInputDescriptorMappings)

        assertEquals("$.verifiableCredential[0]", credentialInputDescriptorMappings[0].nestedPath)
        assertEquals("$.verifiableCredential[1]", credentialInputDescriptorMappings[1].nestedPath)
    }

    @Test
    fun `test build sets the context of the VP as v1 context if no credential is of v2 data model`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, "input-descriptor-id1"),
        )
        val builder = UnsignedLdpVPTokenBuilder(
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
        val (payload, _) = builder.build(mappings)
        val vpPayload = payload as LdpVPToken

        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        assertFalse(vpPayload.context.contains("https://www.w3.org/ns/credentials/v2"))
    }

    @Test
    fun `test build sets the context of the VP as v2 context if at-least credential is of v2 data model`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredentialWithDataModel2, "input-descriptor-id1"),
        )
        val builder = UnsignedLdpVPTokenBuilder(
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
        val (payload, _) = builder.build(mappings)
        val vpPayload = payload as LdpVPToken

        assertFalse(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        assertTrue(vpPayload.context.contains("https://www.w3.org/ns/credentials/v2"))
    }
}
