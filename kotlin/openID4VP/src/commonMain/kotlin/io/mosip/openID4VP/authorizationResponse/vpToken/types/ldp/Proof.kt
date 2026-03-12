package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import kotlinx.serialization.Serializable

@Serializable
class Proof(
    val type: String,
    val created: String,
    val challenge: String,
    val domain: String,
    var proofValue: String? = null,
    var jws: String? = null,
    val proofPurpose: String = "authentication",
    var verificationMethod: String,
    var cryptosuite: String? = null
)