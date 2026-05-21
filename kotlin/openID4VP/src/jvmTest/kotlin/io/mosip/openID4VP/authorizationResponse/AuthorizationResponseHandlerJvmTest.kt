package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.FormatType.LDP_VC
import io.mosip.openID4VP.constants.FormatType.MSO_MDOC
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2018
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.sampleMdoc
import io.mosip.openID4VP.testData.sampleVcSdJwtWithNoHolderBinding
import io.mosip.openID4VP.wallet.Credential
import org.junit.Test
import kotlin.test.assertFalse

// This serves as an integration test to ensure that the overall flows are working
class AuthorizationResponseHandlerJvmTest {
    @Test
    fun `should send a VC successfully`() {
        val matchingCredentials: Map<String, List<Credential>> = mapOf(
            "input-descriptor-id1" to listOf(Credential(LDP_VC, ldpCredential1, "cred-id-1")),
            "input-descriptor-id2" to listOf(Credential(MSO_MDOC, sampleMdoc, "cred-id-2")),
            "input-descriptor-id3" to listOf(Credential(FormatType.VC_SD_JWT, sampleVcSdJwtWithNoHolderBinding, "cred-id-3"))
        )
        val vpTokenSigningResults = listOf<VPTokenSigningResult>()
        val authorizationRequest = authorizationRequestForResponseModeJWT
        val responseUri = authorizationRequest.responseUri!!
        val authorizationResponseHandler = AuthorizationResponseHandler()

        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = matchingCredentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUri,
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