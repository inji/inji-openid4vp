package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonValue

enum class RequestUriMethod(@JsonValue val value: String) {
    GET("get"),
    POST("post");

    companion object {
        fun fromValue(value: String): RequestUriMethod? =
            entries.find { it.value.equals(value, ignoreCase = true) }
    }

    fun toHttpMethod(): HttpMethod = when (this) {
        GET -> HttpMethod.GET
        POST -> HttpMethod.POST
    }
}
