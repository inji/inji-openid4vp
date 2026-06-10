package io.mosip.openID4VP.constants

enum class EncryptionMethod(val value: String) {
    A256GCM("A256GCM");

    companion object {
        fun fromValue(value: String): EncryptionMethod? {
            return entries.find { it.value == value }
        }
    }
}