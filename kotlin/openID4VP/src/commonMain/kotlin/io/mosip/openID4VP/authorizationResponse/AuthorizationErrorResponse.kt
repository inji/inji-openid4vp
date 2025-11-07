package io.mosip.openID4VP.authorizationResponse

import com.google.gson.annotations.SerializedName
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.encodeToJsonString

private val className: String = AuthorizationErrorResponse::class.simpleName!!

data class AuthorizationErrorResponse(
    @SerializedName("error") val error: String,
    @SerializedName("error_description") val errorDescription: String,
    val state: String?,
)

fun AuthorizationErrorResponse.toJsonEncodedMap(): Map<String, String> {
    return buildMap {
        put("error", error)
        put("error_description", errorDescription)
        state?.let { put("state", it) }
    }
}
