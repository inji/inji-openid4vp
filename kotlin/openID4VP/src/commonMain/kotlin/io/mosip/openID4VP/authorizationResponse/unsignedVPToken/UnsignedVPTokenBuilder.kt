package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.constants.SpecVersion

internal interface UnsignedVPTokenBuilder {
    val specVersion: SpecVersion
    val authorizationRequest: AuthorizationRequest
    val walletMetadata: WalletMetadata?
    fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Any?, List<UnsignedVPToken>>
}