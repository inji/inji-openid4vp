package io.mosip.openID4VP.authorizationResponse

import com.google.gson.annotations.SerializedName
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.getObjectMapper

private val className: String = AuthorizationResponse::class.simpleName!!

sealed class AuthorizationResponse {
    abstract val state: String?

    data class PresentationExchange(
        @SerializedName("presentation_submission") val presentationSubmission: PresentationSubmission,
        @SerializedName("vp_token") val vpToken: VPTokenType,
        override val state: String?,
    ) : AuthorizationResponse()

    data class Dcql(
        val vpToken: Map<String, List<VPToken>>,
        override val state: String?,
    ) : AuthorizationResponse()
}

fun AuthorizationResponse.toJsonEncodedMap(): Map<String, String> {
    return when (this) {
        is AuthorizationResponse.PresentationExchange -> buildMap {
            put("vp_token", encodeToJsonString<VPTokenType>(vpToken, "vp_token", className))
            put(
                "presentation_submission",
                encodeToJsonString<PresentationSubmission>(
                    presentationSubmission,
                    "presentation_submission",
                    className
                )
            )
            state?.let<String, Unit> { put("state", it) }
        }
        is AuthorizationResponse.Dcql -> buildMap {
            put("vp_token", getObjectMapper().writeValueAsString(vpToken))
            state?.let<String, Unit> { put("state", it) }
        }
    }
}
