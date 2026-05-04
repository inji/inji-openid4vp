package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = WalletMetadata::class.simpleName!!

internal fun parseClientIdPrefixesSupported(clientIdPrefixesSupported: List<String>?): List<ClientIdPrefix> {
    if (clientIdPrefixesSupported == null) {
        return listOf(ClientIdPrefix.PRE_REGISTERED)
    }
    return clientIdPrefixesSupported.map { value ->
        ClientIdPrefix.fromValue(value) ?: throw OpenID4VPExceptions.InvalidData(
            "Invalid ClientIdPrefix value: $value. Its is not supported by the library.",
            className
        )
    }
}

internal fun parseRequestObjectSigningAlgValuesSupported(values: List<String>?): List<RequestSigningAlgorithm>? {
    if (values == null) return null
    return values.map { value ->
        RequestSigningAlgorithm.entries.find { it.value == value } ?: throw OpenID4VPExceptions.InvalidData(
            "Invalid RequestSigningAlgorithm value: $value. Its is not supported by the library.",
            className
        )
    }
}

internal fun parseAuthorizationEncryptionAlgValuesSupported(values: List<String>?): List<KeyManagementAlgorithm>? {
    if (values == null) return null
    return values.map { value ->
        KeyManagementAlgorithm.entries.find { it.value == value } ?: throw OpenID4VPExceptions.InvalidData(
            "Invalid KeyManagementAlgorithm value: $value. Its is not supported by the library.",
            className
        )
    }
}

internal fun parseAuthorizationEncryptionEncValuesSupported(values: List<String>?): List<ContentEncryptionAlgorithm>? {
    if (values == null) return null
    return values.map { value ->
        ContentEncryptionAlgorithm.entries.find { it.value == value } ?: throw OpenID4VPExceptions.InvalidData(
            "Invalid ContentEncryptionAlgorithm value: $value. Its is not supported by the library.",
            className
        )
    }
}
