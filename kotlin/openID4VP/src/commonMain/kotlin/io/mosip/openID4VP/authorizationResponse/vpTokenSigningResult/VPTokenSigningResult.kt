package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult

data class VPTokenSigningResult(
    val id: String,
    val signedData: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VPTokenSigningResult) return false
        return signedData.contentEquals(other.signedData) && this.id == other.id
    }

    override fun hashCode(): Int = signedData.contentHashCode()
}