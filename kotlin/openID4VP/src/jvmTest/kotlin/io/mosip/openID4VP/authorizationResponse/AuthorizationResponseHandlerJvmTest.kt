package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
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
        val vpTokenSigningResult = mapOf(
            LDP_VC to LdpVPTokenSigningResult(
                "signed",
                "proofValue",
                Ed25519Signature2018.value
            ),
            MSO_MDOC to MdocVPTokenSigningResult(mapOf("org.iso.18013.5.1.mDL" to DeviceAuthentication("signed", "ES256"))),
            FormatType.VC_SD_JWT to SdJwtVPTokenSigningResult(mapOf())
        )
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
            vpTokenSigningResults = vpTokenSigningResult,
            responseUri = responseUri
        )
        assertFalse(true)
    }
}