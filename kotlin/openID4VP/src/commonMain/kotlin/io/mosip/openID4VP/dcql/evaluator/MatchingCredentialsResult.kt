package io.mosip.openID4VP.dcql.evaluator

import io.mosip.openID4VP.dcql.query.ClaimsQuery
import io.mosip.openID4VP.dcql.query.CredentialSetQuery

data class MatchingCredentialsResult(
    val success: Boolean,
    val queryMatches: Map<String, QueryMatchResult>,
    val credentialSets: List<CredentialSetQuery>
)

data class QueryMatchResult(
    val matchingCredentials: List<MatchingCredential>? = null,
    val failedClaims: List<ClaimFailure>? = null,
    val failureReason: String? = null,
    val allowMultipleCredentials: Boolean = false
) {
    constructor(
        matchingCredentials: List<MatchingCredential>? = null,
        failedClaims: List<ClaimFailure>? = null,
        failureReason: DCQLEvaluationErrorCodes?,
        allowMultipleCredentials: Boolean = false
    ) : this(
        matchingCredentials = matchingCredentials,
        failedClaims = failedClaims,
        failureReason = failureReason?.value,
        allowMultipleCredentials = allowMultipleCredentials
    )
}

data class MatchingCredential(
    val credentialId: String,
    val matchingClaims: List<ClaimsQuery>
)

data class ClaimFailure(
    val claim: ClaimsQuery,
    val reason: String
) {
    constructor(claim: ClaimsQuery, reason: DCQLEvaluationErrorCodes) : this(
        claim = claim,
        reason = reason.value
    )
}
