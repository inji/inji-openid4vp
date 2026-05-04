package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

data class WalletMetadata(
    @JsonProperty("vp_formats_supported")
    var vpFormatsSupported: Map<VPFormatType, VPFormatSupported>? = getDefaultVpFormatsSupported(),

    @JsonProperty("client_id_prefixes_supported")
    var clientIdPrefixesSupported: List<ClientIdPrefix>? = getDefaultClientIdPrefixesSupported(),

    @JsonProperty("request_object_signing_alg_values_supported")
    var requestObjectSigningAlgValuesSupported: List<RequestSigningAlgorithm>? = getDefaultRequestSigningAlgorithmSupported(),

    @JsonProperty("authorization_encryption_alg_values_supported")
    var authorizationEncryptionAlgValuesSupported: List<KeyManagementAlgorithm>? = getDefaultKeyManagementAlgorithmSupported(),

    @JsonProperty("authorization_encryption_enc_values_supported")
    var authorizationEncryptionEncValuesSupported: List<ContentEncryptionAlgorithm>? = getDefaultContentEncryptionAlgorithmSupported(),

    @JsonProperty("response_types_supported")
    var responseTypeSupported: List<ResponseType>? = getDefaultResponseTypeSupported()
) {
    init {
        vpFormatsSupported = vpFormatsSupported ?: getDefaultVpFormatsSupported()
        clientIdPrefixesSupported = clientIdPrefixesSupported ?: getDefaultClientIdPrefixesSupported()
        requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported ?: getDefaultRequestSigningAlgorithmSupported()
        authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported ?: getDefaultKeyManagementAlgorithmSupported()
        authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported ?: getDefaultContentEncryptionAlgorithmSupported()
        responseTypeSupported = responseTypeSupported ?: getDefaultResponseTypeSupported()
    }

    companion object {
        private val className = WalletMetadata::class.simpleName!!

        fun <T : Enum<T>> parseEnum(
            value: String,
            validEntries: Array<T>,
            typeName: String
        ): T {
            return validEntries.find { it.name == value } ?: throw OpenID4VPExceptions.InvalidData(
                "Invalid $typeName value: $value. Its is not supported by the library.",
                className
            )
        }
    }

    constructor(): this(
        vpFormatsSupported = getDefaultVpFormatsSupported(),
        clientIdPrefixesSupported = getDefaultClientIdPrefixesSupported(),
        requestObjectSigningAlgValuesSupported = getDefaultRequestSigningAlgorithmSupported(),
        authorizationEncryptionAlgValuesSupported = getDefaultKeyManagementAlgorithmSupported(),
        authorizationEncryptionEncValuesSupported = getDefaultContentEncryptionAlgorithmSupported(),
        responseTypeSupported = getDefaultResponseTypeSupported()
    )

    @Deprecated("This constructor accepts all field type as String, use the new constructor instead.")
    constructor(
        vpFormatsSupported: Map<String, VPFormatSupported>,
        clientIdPrefixesSupported: List<String>? = null,
        requestObjectSigningAlgValuesSupported: List<String>? = null,
        authorizationEncryptionAlgValuesSupported: List<String>? = null,
        authorizationEncryptionEncValuesSupported: List<String>? = null,
    ) : this(
        vpFormatsSupported = vpFormatsSupported.mapKeys { key ->
            parseEnum(key.key, VPFormatType.entries.toTypedArray(), "VPFormatType")
        },
        clientIdPrefixesSupported = clientIdPrefixesSupported?.map {
            parseEnum(it, ClientIdPrefix.entries.toTypedArray(), "ClientIdPrefix")
        } ?: listOf(ClientIdPrefix.PRE_REGISTERED),
        requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported?.map {
            parseEnum(it, RequestSigningAlgorithm.entries.toTypedArray(), "RequestSigningAlgorithm")
        },
        authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported?.map {
            parseEnum(it, KeyManagementAlgorithm.entries.toTypedArray(), "KeyManagementAlgorithm")
        },
        authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported?.map {
            parseEnum(it, ContentEncryptionAlgorithm.entries.toTypedArray(), "ContentEncryptionAlgorithm")
        }
    )

    fun encode(specVersion: SpecVersion): String {
        return when (specVersion) {
            SpecVersion.V1 -> {
                val mapper = ObjectMapper()
                mapper.writeValueAsString(this)
            }
            SpecVersion.DRAFT_23 -> {
                val walletMetadataDict = mutableMapOf<String, Any>()

                val vpFormats = vpFormatsSupported?.entries?.associate { (key, value) ->
                    val formatKey = key.value
                    val algValues = value.toAlgValuesSupported()
                    if (algValues != null) {
                        formatKey to mapOf("alg_values_supported" to algValues)
                    } else {
                        formatKey to emptyMap()
                    }
                } ?: emptyMap()

                walletMetadataDict["presentation_definition_uri_supported"] = true
                walletMetadataDict["vp_formats_supported"] = vpFormats
                walletMetadataDict["client_id_schemes_supported"] = clientIdPrefixesSupported?.map {
                    ClientIdPrefix.toClientIdScheme(it)
                } ?: emptyList<String>()

                requestObjectSigningAlgValuesSupported?.let {
                    walletMetadataDict["request_object_signing_alg_values_supported"] = it.map { alg -> alg.value }
                }
                authorizationEncryptionAlgValuesSupported?.let {
                    walletMetadataDict["authorization_encryption_alg_values_supported"] = it.map { alg -> alg.value }
                }
                authorizationEncryptionEncValuesSupported?.let {
                    walletMetadataDict["authorization_encryption_enc_values_supported"] = it.map { enc -> enc.value }
                }
                walletMetadataDict["response_types_supported"] = responseTypeSupported?.map { it.value } ?: emptyList<String>()

                val mapper = ObjectMapper()
                mapper.writeValueAsString(walletMetadataDict)
            }
        }
    }
}
