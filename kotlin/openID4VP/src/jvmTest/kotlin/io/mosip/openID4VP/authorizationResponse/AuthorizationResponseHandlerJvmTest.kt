package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResultV2
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.FormatType.LDP_VC
import io.mosip.openID4VP.constants.FormatType.MSO_MDOC
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2018
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.sampleMdoc
import io.mosip.openID4VP.testData.sampleVcSdJwtWithNoHolderBinding
import org.junit.Test
import kotlin.test.assertFalse

// This serves as an integration test to ensure that the overall flows are working
class AuthorizationResponseHandlerJvmTest {
    @Test
    fun `should send a VC successfully`() {
        val matchingCredentials: Map<String, Map<FormatType, List<Any>>> = mapOf(
            "input-descriptor-id1" to mapOf(LDP_VC to listOf(ldpCredential1)),
            "input-descriptor-id2" to mapOf(MSO_MDOC to listOf(sampleMdoc)),
            "input-descriptor-id3" to mapOf(
                FormatType.VC_SD_JWT to listOf(
                    sampleVcSdJwtWithNoHolderBinding
                )
            )
        )
        val vpTokenSigningResults = listOf<VPTokenSigningResultV2>()
        val authorizationRequest = authorizationRequestForResponseModeJWT
        val responseUri = authorizationRequest.responseUri!!
        val authorizationResponseHandler = AuthorizationResponseHandler()

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = matchingCredentials,
            holderId = "did:example:holder",
            authorizationRequest = authorizationRequest,
            responseUri = responseUri,
            signatureSuite = Ed25519Signature2018.value,
            nonce = "wallet-nonce-value",
        )

        authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults,
            responseUri = responseUri
        )
        assertFalse(true)
    }
}