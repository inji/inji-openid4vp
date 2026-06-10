package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult

data class VPTokenSigningResult(
    val signedData: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VPTokenSigningResult) return false
        return signedData.contentEquals(other.signedData)
    }

    override fun hashCode(): Int = signedData.contentHashCode()
}