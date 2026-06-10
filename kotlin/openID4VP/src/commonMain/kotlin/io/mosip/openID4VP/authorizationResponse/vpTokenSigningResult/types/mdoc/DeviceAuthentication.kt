package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = DeviceAuthentication::class.simpleName!!

data class DeviceAuthentication(
    val signature: ByteArray,
    val algorithm: String
) {
    fun validate() {
        require(signature.isNotEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("mdoc_vp_token_signing_result", "device_authentication", "signature"),
                "signature",
                className
            )
        }
        require(algorithm != "null" && validateField(algorithm, "String")) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("mdoc_vp_token_signing_result", "device_authentication", "algorithm"),
                "algorithm",
                className
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DeviceAuthentication) return false
        return signature.contentEquals(other.signature) && algorithm == other.algorithm
    }

    override fun hashCode(): Int = 31 * signature.contentHashCode() + algorithm.hashCode()
}