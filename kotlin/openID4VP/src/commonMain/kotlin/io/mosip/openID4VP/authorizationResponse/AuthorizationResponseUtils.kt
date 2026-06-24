package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.getVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData

fun Map<FormatType, UnsignedVPToken>.toJsonString(): String? {
    val formattedMap = this.mapKeys { (key, _) -> key.value }
    val objectMapper = getObjectMapper()

    return objectMapper.writeValueAsString(formattedMap)
}

internal fun constructSigningResults(
    unsignedVPTokenResults: Map<FormatType, Pair<Any?, List<UnsignedVPToken>>>,
    signingResults: List<VPTokenSigningResult>,
    className: String
): Map<FormatType, List<VPTokenSigningResult>> {
    val expectedIdentifiers = unsignedVPTokenResults.values.flatMap { it.second.map { token -> token.id } }.toSet()
    val unexpectedIdentifiers = signingResults.map { it.id }.toSet().subtract(expectedIdentifiers)
    if (unexpectedIdentifiers.isNotEmpty()) {
        throw InvalidData(
            "Unexpected VP token signing result for credential identifier(s): ${unexpectedIdentifiers.sorted().joinToString(", ")}",
            className
        )
    }

    val reconstructedSigningResults = mutableMapOf<FormatType, MutableList<VPTokenSigningResult>>()
    unsignedVPTokenResults.entries.forEach { (format, pair) ->
        val unsignedTokens = pair.second
        unsignedTokens.forEach { unsignedToken ->
            val vpTokenSigningResult =
                getVPTokenSigningResult(signingResults, unsignedToken.id, className)

            reconstructedSigningResults.getOrPut(format) { mutableListOf() }.add(vpTokenSigningResult)
        }
    }

    return reconstructedSigningResults.toMap()
}