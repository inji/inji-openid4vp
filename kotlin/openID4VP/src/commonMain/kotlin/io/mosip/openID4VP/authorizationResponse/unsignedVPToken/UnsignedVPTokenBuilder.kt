package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.constants.SpecVersion

internal interface UnsignedVPTokenBuilder {
    val specVersion: SpecVersion
    val authorizationRequest: AuthorizationRequest
    val walletConfig: WalletConfig
    // DCQL flow
    fun build(credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>): Pair<Any?, List<UnsignedVPToken>>
    // PE flow — declared on concrete classes with @JvmName("buildForPex") to avoid JVM type-erasure clash
}