package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonProperty

enum class EncryptionAlgorithm(val value: String) {
    @JsonProperty("ECDH-ES") ECDH_ES("ECDH-ES");

    companion object {
        fun fromValue(value: String): EncryptionAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}