package io.mosip.openID4VP.evaluator.dcql

import io.mosip.openID4VP.authorizationRequest.dcqlQuery.DCQLQuery
import io.mosip.openID4VP.wallet.Credential

class DCQLHelper {

    fun getMatchingCredentials(
        inputCredentials: List<Credential>,
        dcqlQuery: DCQLQuery
    ): MatchingCredentialsResult {
        return DcqlEvaluator().evaluate(dcqlQuery, inputCredentials)
    }
}
