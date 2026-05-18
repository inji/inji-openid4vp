package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.*

data class WalletConfig @JvmOverloads constructor(
    val vpFormatsSupported: Map<VPFormatType, VPFormatSupported> = getDefaultVpFormatsSupported(),
    val clientIdPrefixesSupported: List<ClientIdPrefix> = getDefaultClientIdPrefixesSupported(),
    val requestObjectSigningAlgValuesSupported: List<RequestSigningAlgorithm>? = getDefaultRequestSigningAlgorithmSupported(),
    val authorizationEncryptionAlgValuesSupported: List<KeyManagementAlgorithm>? = getDefaultKeyManagementAlgorithmSupported(),
    val authorizationEncryptionEncValuesSupported: List<ContentEncryptionAlgorithm>? = getDefaultContentEncryptionAlgorithmSupported(),
    val responseTypesSupported: List<ResponseType> = getDefaultResponseTypeSupported(),
    val isPresentationDefinitionUriSupported: Boolean = true,
    val supportedRequestUriMethods: List<RequestUriMethod> = listOf(RequestUriMethod.GET, RequestUriMethod.POST),
    val trustedVerifiers: List<Verifier> = emptyList()
) {
    fun toWalletMetadata(): WalletMetadata {
        return WalletMetadata(
            vpFormatsSupported = vpFormatsSupported,
            clientIdPrefixesSupported = clientIdPrefixesSupported,
            requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
            authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported,
            authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported,
            responseTypeSupported = responseTypesSupported
        )
    }
}
