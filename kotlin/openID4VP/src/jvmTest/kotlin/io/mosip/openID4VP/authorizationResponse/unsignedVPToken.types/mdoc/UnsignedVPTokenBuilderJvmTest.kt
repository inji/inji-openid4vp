package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import io.mockk.spyk
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.constants.FormatType.MSO_MDOC
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UnsignedVPTokenBuilderJvmTest {

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(
            presentationDefinitionMap,
            PresentationDefinitionSerializer
        ),
        responseUri = responseUrl,
        redirectUri = null,
        nonce = verifierNonce,
        state = null,
        walletNonce = walletNonce,
    )

    @Test
    fun `should use provided parameters correctly in token creation`() {
        val spyBuilder = spyk(
            UnsignedMdocVPTokenBuilder(
                authorizationRequest = testAuthorizationRequest,
                specVersion = SpecVersion.DRAFT_23,
                responseUri = responseUrl,
                mdocGeneratedNonce = walletNonce
            )
        )

        spyBuilder.build(listOf(CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id")))
        verify {
            spyBuilder.build(match {
                assertTrue(it.size == 1)
                val credentialInputDescriptorMapping = it.first()
                assertEquals(MSO_MDOC, credentialInputDescriptorMapping.format)
                assertEquals(mdocCredential, credentialInputDescriptorMapping.credential)
                ("input-descriptor-id" == credentialInputDescriptorMapping.inputDescriptorId)
            })
        }
    }

    @Test
    fun `should throw exception when duplicate docType is found`() {
        val mdocCredentials = listOf(mdocCredential, mdocCredential)

        val exception = assertFailsWith<InvalidData> {
            UnsignedMdocVPTokenBuilder(
                authorizationRequest = testAuthorizationRequest,
                specVersion = SpecVersion.DRAFT_23,
                responseUri = responseUrl,
                mdocGeneratedNonce = walletNonce
            ).build(listOf(
                CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id-1"),
                CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id-2")
            ))
        }

        assertEquals("Duplicate Mdoc Credentials with same doctype found", exception.message)
    }

    @Test
    fun `should create token with correct structure and payload format`() {
        val mdocCredentials = listOf(mdocCredential)

        val (_, unsignedVPToken) = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce
        ).build(listOf(CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id")))

        val docType = unsignedVPToken.docTypeToDeviceAuthenticationBytes.keys.first()
        val authData = unsignedVPToken.docTypeToDeviceAuthenticationBytes[docType]

        assertNotNull(docType)
        assertFalse(docType.isEmpty())

        assertNotNull(authData)
        assertTrue(authData is String)

        // Check if the payload is a valid hex string
        assertTrue(authData.matches("[0-9A-Fa-f]+".toRegex()))
    }

    @Test
    fun `should create UnsignedMdocVPToken with valid input`() {
        val mdocCredentials = listOf(mdocCredential)

        val (payload, unsignedVPToken) = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce
        ).build(listOf(CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id")))

        // Check vpTokenSigningPayload
        assertNull(payload)

        // Check unsignedVPToken
        assertTrue(unsignedVPToken.docTypeToDeviceAuthenticationBytes.isNotEmpty())
        assertEquals(1, unsignedVPToken.docTypeToDeviceAuthenticationBytes.size)
    }

}