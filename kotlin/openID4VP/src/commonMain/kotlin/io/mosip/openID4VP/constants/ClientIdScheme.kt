package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonProperty

internal enum class ClientIdScheme(val value: String) {
    @JsonProperty("pre-registered") PRE_REGISTERED("pre-registered"),
    @JsonProperty("redirect_uri") REDIRECT_URI("redirect_uri"),
    @JsonProperty("did") DID("did"),
    @JsonProperty("x509_san_dns") X509_SAN_DNS("x509_san_dns");

    companion object {
        fun fromValue(value: String): ClientIdScheme? {
            return entries.find { it.value == value }
        }
    }
}

