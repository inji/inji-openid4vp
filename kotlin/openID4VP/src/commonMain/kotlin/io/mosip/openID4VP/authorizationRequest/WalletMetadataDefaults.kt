package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.VPFormatType

fun getDefaultResponseTypeSupported() =
    listOf(ResponseType.VP_TOKEN)

fun getDefaultRequestSigningAlgorithmSupported() =
    listOf(RequestSigningAlgorithm.EdDSA)

fun getDefaultKeyManagementAlgorithmSupported() =
    listOf(KeyManagementAlgorithm.ECDH_ES)

fun getDefaultContentEncryptionAlgorithmSupported() =
    listOf(ContentEncryptionAlgorithm.A256GCM)

fun getDefaultClientIdPrefixesSupported() =
    listOf(ClientIdPrefix.PRE_REGISTERED, ClientIdPrefix.REDIRECT_URI, ClientIdPrefix.DECENTRALIZED_IDENTIFIER)

fun getDefaultVpFormatsSupported(): Map<VPFormatType, VPFormatSupported> =
    mapOf(
        VPFormatType.LDP_VC to LdpVcFormatSupported(),
        VPFormatType.MSO_MDOC to MsoMdocVcFormatSupported(),
        VPFormatType.DC_SD_JWT to SdJwtVcFormatSupported()
    )
