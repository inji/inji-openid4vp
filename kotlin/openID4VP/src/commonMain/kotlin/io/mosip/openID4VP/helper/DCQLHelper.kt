package io.mosip.openID4VP.helper

import io.mosip.openID4VP.dcql.evaluator.DcqlEvaluator
import io.mosip.openID4VP.dcql.evaluator.MatchingCredentialsResult
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.wallet.Credential

class DCQLHelper {

    fun getMatchingCredentials(
        inputCredentials: List<Credential>,
        dcqlQuery: DCQLQuery
    ): MatchingCredentialsResult {
        return DcqlEvaluator().evaluate(dcqlQuery, inputCredentials)
    }
}