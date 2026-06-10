package io.mosip.openID4VP.wallet

import io.mosip.openID4VP.constants.FormatType

data class Credential(
    val format: FormatType,
    val data: Any,
    val credentialId: String
)
