package io.mosip.openID4VP.authorizationResponse

import com.google.gson.annotations.SerializedName

data class AuthorizationErrorResponse(
    @SerializedName("error") val error: String,
    @SerializedName("error_description") val errorDescription: String,
    val state: String?,
)

fun AuthorizationErrorResponse.toJsonEncodedMap(): Map<String, String> {
    return buildMap {
        put("error", error)
        put("error_description", errorDescription)
        state?.takeIf { it.isNotBlank() }?.let { put("state", it) }
    }
}
