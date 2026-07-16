package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.google.gson.annotations.SerializedName
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
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
            state?.let { put("state", it) }
        }
        is AuthorizationResponse.Dcql -> buildMap {
            put("vp_token", encodeToJsonString(vpToken, "vp_token", className))
            state?.let { put("state", it) }
        }
    }
}

fun AuthorizationResponse.toMap(): Map<String, Any> {
    val objectMapper = getObjectMapper().copy().setSerializationInclusion(JsonInclude.Include.NON_NULL)
    return when (this) {
        is AuthorizationResponse.PresentationExchange -> buildMap {
            put("vp_token", objectMapper.convertValue(vpToken, object : TypeReference<Any>() {}))
            put(
                "presentation_submission",
                objectMapper.convertValue(presentationSubmission, object : TypeReference<Map<String, Any>>() {})
            )
            state?.let { put("state", it) }
        }
        is AuthorizationResponse.Dcql -> buildMap {
            put("vp_token", objectMapper.convertValue(vpToken, object : TypeReference<Any>() {}))
            state?.let { put("state", it) }
        }
    }
}