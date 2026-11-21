package io.mosip.openID4VP.authorizationRequest

data class CertIdentity(
    val verifiedDnsName: String,
    val organization: String?,
    val commonName: String?,
    val validUntil: String // ISO 8601 — e.g. "2027-06-01T00:00:00Z"
)