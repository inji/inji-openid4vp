package io.mosip.openID4VP.constants

enum class ProofType(val value: String) {
    Ed25519Signature2020("Ed25519Signature2020"),
    JsonWebSignature2020("JsonWebSignature2020");

    companion object {
        fun fromValue(value: String): ProofType? {
            return entries.find { it.value == value }
        }
    }
}
