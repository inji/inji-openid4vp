package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData

internal fun getVPTokenSigningResult(
    vpTokenSigningResults: List<VPTokenSigningResult>,
    identifier: String?,
    className: String
): VPTokenSigningResult {
    val matchingSigningResults: List<VPTokenSigningResult> =
        vpTokenSigningResults.filter { it.id == identifier }
    if (matchingSigningResults.isEmpty() || matchingSigningResults.size > 1) {
        throw OpenID4VPExceptions.MissingInput(
            "",
            "Missing VP token signing result for credential identifier $identifier",
            className
        )
    }

    val vPTokenSigningResult = matchingSigningResults.first()
    return vPTokenSigningResult
}

internal fun getUnsignedVPToken(
    unsignedVPTokens: List<UnsignedVPToken>,
    identifier: String,
    className: String
): UnsignedVPToken {
    val matchingUnsignedVPTokens = unsignedVPTokens.filter { it.id == identifier }
    if (matchingUnsignedVPTokens.isEmpty() || matchingUnsignedVPTokens.size > 1) {
        throw OpenID4VPExceptions.InvalidData(
            "Missing unsigned VP token for id: $identifier",
            className
        )
    }

    val unsignedVPToken = matchingUnsignedVPTokens.first()
    return unsignedVPToken
}

internal fun getMatchingCredentialQuery(
    dcqlRequest: AuthorizationDcqlRequest,
    credentialQueryId: String,
    className: String
): CredentialQuery =
    (dcqlRequest.dcqlQuery.credentials.firstOrNull { it.id == credentialQueryId }
        ?: throw InvalidData(
            "No matching credential query found for credential query id: ${credentialQueryId}",
            className
        ))