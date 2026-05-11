package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult

data class VPTokenSigningResult(
    val signedData: ByteArray
) {
    @Deprecated("Use ByteArray constructor instead", ReplaceWith("VPTokenSigningResult(signedData.toByteArray(Charsets.UTF_8))"))
    constructor(signedData: String) : this(signedData.toByteArray(Charsets.UTF_8))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VPTokenSigningResult) return false
        return signedData.contentEquals(other.signedData)
    }

    override fun hashCode(): Int = signedData.contentHashCode()
}