package io.mosip.openID4VP.evaluator.dcql

import io.mosip.openID4VP.constants.FormatType

internal interface ProcessedCredential {
    val credentialId: String
    val credentialFormat: FormatType
}

internal data class W3cProcessedCredential(
    override val credentialId: String,
    override val credentialFormat: FormatType,
    val claims: Map<String, Any>
) : ProcessedCredential

internal data class MdocProcessedCredential(
    override val credentialId: String,
    override val credentialFormat: FormatType = FormatType.MSO_MDOC,
    val namespaces: Map<String, Map<String, Any>>
) : ProcessedCredential

internal data class SdJwtProcessedCredential(
    override val credentialId: String,
    override val credentialFormat: FormatType,
    val claims: Map<String, Any>
) : ProcessedCredential
