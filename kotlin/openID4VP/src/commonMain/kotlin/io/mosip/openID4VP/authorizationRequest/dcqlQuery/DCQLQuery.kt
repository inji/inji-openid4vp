package io.mosip.openID4VP.authorizationRequest.dcqlQuery

import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val VALID_ID_PATTERN = Regex("^[a-zA-Z0-9_-]+$")

data class DCQLQuery(
    val credentials: List<CredentialQuery>,
    val credentialSets: List<CredentialSetQuery>? = null
) {
    companion object {
        private const val CLASS_NAME = "DCQLQuery"
    }

    init {
        validate()
    }

    private fun validate() {
        if (credentials.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("dcql_query", "credentials"), null, CLASS_NAME
            )
        }

        val credentialQueryIds = credentials.map { it.id }
        if (credentialQueryIds.size != credentialQueryIds.toSet().size) {
            throw OpenID4VPExceptions.InvalidData(
                "Credential Query ids must be unique within dcql_query",
                CLASS_NAME
            )
        }

        for (credential in credentials) {
            credential.validate()
        }

        credentialSets?.let { sets ->
            if (sets.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("dcql_query", "credential_sets"), null, CLASS_NAME
                )
            }
            for (credentialSet in sets) {
                credentialSet.validateCredentialIdReferences(credentialQueryIds.toSet())
            }
        }
    }
}

data class CredentialQuery(
    val id: String,
    val format: String,
    val multiple: Boolean = false,
    val meta: Map<String, Any> = emptyMap(),
    val requireCryptographicHolderBinding: Boolean = true,
    val claims: List<ClaimsQuery>? = null,
    val claimSets: List<List<String>>? = null
) {
    companion object {
        private const val CLASS_NAME = "CredentialQuery"
    }

    internal fun validate() {
        if (!VALID_ID_PATTERN.matches(id)) {
            throw OpenID4VPExceptions.InvalidData(
                "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                CLASS_NAME
            )
        }

        if (format.isBlank()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("credential_query", "format"), null, CLASS_NAME
            )
        }

        claims?.let { claimsList ->
            if (claimsList.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_query", "claims"), null, CLASS_NAME
                )
            }

            val claimIds = claimsList.mapNotNull { it.id }
            if (claimIds.size != claimIds.toSet().size) {
                throw OpenID4VPExceptions.InvalidData(
                    "Claim ids must be unique within a Credential Query",
                    CLASS_NAME
                )
            }

            for (claim in claimsList) {
                claim.validate(isCredentialSetsAvailable = claimSets != null)
            }
        }

        claimSets?.let { sets ->
            if (claims == null) {
                throw OpenID4VPExceptions.InvalidData(
                    "claim_sets must not be present when claims is absent",
                    CLASS_NAME
                )
            }
            if (sets.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_query", "claim_sets"), null, CLASS_NAME
                )
            }
            val validClaimIds = claims.mapNotNull { it.id }.toSet()
            for (claimSet in sets) {
                if (claimSet.isEmpty()) {
                    throw OpenID4VPExceptions.InvalidInput(
                        listOf("credential_query", "claim_sets"), null, CLASS_NAME
                    )
                }
                for (claimId in claimSet) {
                    if (!validClaimIds.contains(claimId)) {
                        throw OpenID4VPExceptions.InvalidData(
                            "claim_sets references unknown claim id '$claimId'",
                            CLASS_NAME
                        )
                    }
                }
            }
        }
    }
}

data class CredentialSetQuery(
    val options: List<List<String>>,
    val required: Boolean = true
) {
    companion object {
        private const val CLASS_NAME = "CredentialSetQuery"
    }

    init {
        validate()
    }

    private fun validate() {
        if (options.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("credential_set_query", "options"), null, CLASS_NAME
            )
        }
        for (option in options) {
            if (option.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_set_query", "options"), null, CLASS_NAME
                )
            }
        }
    }

    internal fun validateCredentialIdReferences(credentialQueryIds: Set<String>) {
        for (option in options) {
            for (credentialQueryIdentifier in option) {
                if (!credentialQueryIds.contains(credentialQueryIdentifier)) {
                    throw OpenID4VPExceptions.InvalidData(
                        "credential_sets references unknown credential id '$credentialQueryIdentifier'",
                        CLASS_NAME
                    )
                }
            }
        }
    }
}

sealed class ClaimValue {
    data class StringValue(val value: String) : ClaimValue()
    data class IntValue(val value: Int) : ClaimValue()
    data class BoolValue(val value: Boolean) : ClaimValue()

    companion object {
        fun from(value: Any?): ClaimValue {
            return when (value) {
                is Boolean -> BoolValue(value)
                is Int -> IntValue(value)
                is Long -> IntValue(value.toInt())
                is Number -> IntValue(value.toInt())
                is String -> StringValue(value)
                else -> throw IllegalArgumentException("Claim value must be a string, integer, or boolean")
            }
        }
    }
}

data class ClaimsQuery(
    val id: String? = null,
    val path: List<Any?>,
    val values: List<ClaimValue>? = null
) {
    companion object {
        private const val CLASS_NAME = "ClaimsQuery"
    }

    internal fun validate(isCredentialSetsAvailable: Boolean) {
        if (isCredentialSetsAvailable && id == null) {
            throw OpenID4VPExceptions.InvalidData(
                "Claims with claim_sets must have an id",
                CLASS_NAME
            )
        }

        id?.let {
            if (!VALID_ID_PATTERN.matches(it)) {
                throw OpenID4VPExceptions.InvalidData(
                    "Claims Query id must consist of alphanumeric, underscore or hyphen characters",
                    CLASS_NAME
                )
            }
        }

        if (path.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("claims_query", "path"), null, CLASS_NAME
            )
        }

        values?.let {
            if (it.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("claims_query", "values"), null, CLASS_NAME
                )
            }
        }
    }
}
