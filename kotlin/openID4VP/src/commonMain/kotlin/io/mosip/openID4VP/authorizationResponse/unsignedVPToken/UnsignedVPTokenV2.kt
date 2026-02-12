package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

import io.mosip.openID4VP.constants.FormatType

data class UnsignedVPTokenV2(

    val format: FormatType,

    val holderKeyReference: String,

    val signatureAlgorithm: String,

    val dataToSign: String
)
