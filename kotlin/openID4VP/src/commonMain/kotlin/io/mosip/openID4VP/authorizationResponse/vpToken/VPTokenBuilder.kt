package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult

internal interface VPTokenBuilder {
    fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<VPToken>, List<DescriptorMap>, Int>

    fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>>
}