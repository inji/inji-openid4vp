package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import io.mosip.openID4VP.constants.FormatType

class ByteArrayToBase64UrlSerializer : StdSerializer<ByteArray>(ByteArray::class.java) {
    override fun serialize(value: ByteArray, gen: JsonGenerator, provider: SerializerProvider) {
        gen.writeString(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value))
    }
}

data class UnsignedVPToken(
    val format: FormatType,
    val holderKeyReference: String,
    val signatureAlgorithm: String,
    @JsonSerialize(using = ByteArrayToBase64UrlSerializer::class)
    val dataToSign: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnsignedVPToken) return false
        return format == other.format &&
            holderKeyReference == other.holderKeyReference &&
            signatureAlgorithm == other.signatureAlgorithm &&
            dataToSign.contentEquals(other.dataToSign)
    }

    override fun hashCode(): Int {
        var result = format.hashCode()
        result = 31 * result + holderKeyReference.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + dataToSign.contentHashCode()
        return result
    }
}