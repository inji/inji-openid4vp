package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.EncryptionMethod
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.VPFormatType

fun getDefaultResponseTypeSupported() =
    listOf(ResponseType.VP_TOKEN)

fun getDefaultSignatureAlgorithmSupported() =
    listOf(SignatureAlgorithm.EdDSA)

fun getDefaultEncryptionAlgorithmSupported() =
    listOf(EncryptionAlgorithm.ECDH_ES)

fun getDefaultEncryptionMethodSupported() =
    listOf(EncryptionMethod.A256GCM)

fun getDefaultClientIdPrefixesSupported() =
    listOf(ClientIdPrefix.PRE_REGISTERED, ClientIdPrefix.REDIRECT_URI, ClientIdPrefix.DECENTRALIZED_IDENTIFIER)

fun getDefaultVpFormatsSupported(): Map<VPFormatType, VPFormatSupported> =
    mapOf(
        VPFormatType.LDP_VC to LdpVpFormatSupported(),
        VPFormatType.MSO_MDOC to MsoMdocVpFormatSupported(),
        VPFormatType.DC_SD_JWT to SdJwtVpFormatSupported()
    )
