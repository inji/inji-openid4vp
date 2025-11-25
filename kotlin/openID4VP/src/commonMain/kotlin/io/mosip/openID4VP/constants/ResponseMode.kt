package io.mosip.openID4VP.constants

enum class ResponseMode(val value: String) {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),

    IAR_POST("iar_post"),
    IAR_POST_JWT("iar_post.jwt"),
}