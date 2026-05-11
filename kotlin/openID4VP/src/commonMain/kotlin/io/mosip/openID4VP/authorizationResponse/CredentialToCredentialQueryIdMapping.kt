package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.constants.FormatType

internal class CredentialToCredentialQueryIdMapping(
    val format: FormatType,
    val credential: Any,
    val credentialQueryId: String
) {
    var identifier: String? = null
}
