package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken

data class LdpVPToken(
    @JsonProperty("@context")
    val context: List<String>,
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<Any>,
    val id: String,
    var holder: String? = null,
    val proof: Proof?,
) : VPToken {
    companion object {
        const val INTERNAL_PATH: String = "VerifiableCredential"
    }
}