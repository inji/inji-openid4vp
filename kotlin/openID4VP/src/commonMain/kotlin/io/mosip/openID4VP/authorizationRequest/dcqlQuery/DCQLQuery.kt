package io.mosip.openID4VP.authorizationRequest.dcqlQuery

import Generated
import io.mosip.openID4VP.authorizationRequest.Validatable
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

private val VALID_ID_PATTERN = Regex("^[a-zA-Z0-9_-]+$")
private const val DCQL_QUERY_CLASS_NAME = "DCQLQuery"
private const val CREDENTIAL_QUERY_CLASS_NAME = "CredentialQuery"
private const val CREDENTIAL_SET_QUERY_CLASS_NAME = "CredentialSetQuery"
private const val CLAIM_VALUE_CLASS_NAME = "ClaimValue"
private const val CLAIMS_QUERY_CLASS_NAME = "ClaimsQuery"

object DCQLQuerySerializer : KSerializer<DCQLQuery> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("DCQLQuery") {
        element("credentials", ListSerializer(JsonObject.serializer()).descriptor)
        element("credential_sets", ListSerializer(JsonObject.serializer()).descriptor, isOptional = true)
    }

    override fun deserialize(decoder: Decoder): DCQLQuery {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw OpenID4VPExceptions.DeserializationFailure(
                listOf("dcql_query"),
                e.message!!,
                DCQL_QUERY_CLASS_NAME
            )
        }

        val jsonObject = try {
            jsonDecoder.decodeJsonElement().jsonObject
        } catch (e: IllegalArgumentException) {
            throw OpenID4VPExceptions.DeserializationFailure(
                listOf("dcql_query"),
                e.message ?: "dcql_query must be a JSON object",
                DCQL_QUERY_CLASS_NAME
            )
        }

        return parseDcqlQuery(jsonObject)
    }

    @Generated
    override fun serialize(encoder: Encoder, value: DCQLQuery) {
        val jsonEncoder = try {
            encoder as JsonEncoder
        } catch (e: ClassCastException) {
            throw OpenID4VPExceptions.JsonEncodingFailed(
                "dcql_query",
                e.message ?: "DCQLQuerySerializer only supports JSON encoding",
                DCQL_QUERY_CLASS_NAME
            )
        }

        jsonEncoder.encodeJsonElement(value.toJsonObject())
    }
}

@Serializable(with = DCQLQuerySerializer::class)
data class DCQLQuery(
    val credentials: List<CredentialQuery>,
    val credentialSets: List<CredentialSetQuery>? = null
) : Validatable {

    init {
        validate()
    }

    override fun validate() {
        if (credentials.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("dcql_query", "credentials"), null, DCQL_QUERY_CLASS_NAME
            )
        }

        val credentialQueryIds = credentials.map { it.id }
        if (credentialQueryIds.size != credentialQueryIds.toSet().size) {
            throw OpenID4VPExceptions.InvalidData(
                "Credential Query ids must be unique within dcql_query",
                DCQL_QUERY_CLASS_NAME
            )
        }

        for (credential in credentials) {
            credential.validate()
        }

        credentialSets?.let { sets ->
            if (sets.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("dcql_query", "credential_sets"), null, DCQL_QUERY_CLASS_NAME
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
    internal fun validate() {
        if (!VALID_ID_PATTERN.matches(id)) {
            throw OpenID4VPExceptions.InvalidData(
                "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                CREDENTIAL_QUERY_CLASS_NAME
            )
        }

        if (format.isBlank()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("credential_query", "format"), null, CREDENTIAL_QUERY_CLASS_NAME
            )
        }

        claims?.let { claimsList ->
            if (claimsList.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_query", "claims"), null, CREDENTIAL_QUERY_CLASS_NAME
                )
            }

            val claimIds = claimsList.mapNotNull { it.id }
            if (claimIds.size != claimIds.toSet().size) {
                throw OpenID4VPExceptions.InvalidData(
                    "Claim ids must be unique within a Credential Query",
                    CREDENTIAL_QUERY_CLASS_NAME
                )
            }

            for (claim in claimsList) {
                claim.validate(isClaimSetsAvailable = claimSets != null)
            }
        }

        claimSets?.let { sets ->
            if (claims == null) {
                throw OpenID4VPExceptions.InvalidData(
                    "claim_sets must not be present when claims is absent",
                    CREDENTIAL_QUERY_CLASS_NAME
                )
            }
            if (sets.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_query", "claim_sets"), null, CREDENTIAL_QUERY_CLASS_NAME
                )
            }
            val validClaimIds = claims.mapNotNull { it.id }.toSet()
            for (claimSet in sets) {
                if (claimSet.isEmpty()) {
                    throw OpenID4VPExceptions.InvalidInput(
                        listOf("credential_query", "claim_sets"), null, CREDENTIAL_QUERY_CLASS_NAME
                    )
                }
                for (claimId in claimSet) {
                    if (!validClaimIds.contains(claimId)) {
                        throw OpenID4VPExceptions.InvalidData(
                            "claim_sets references unknown claim id '$claimId'",
                            CREDENTIAL_QUERY_CLASS_NAME
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
    init {
        validate()
    }

    private fun validate() {
        if (options.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("credential_set_query", "options"), null, CREDENTIAL_SET_QUERY_CLASS_NAME
            )
        }
        for (option in options) {
            if (option.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_set_query", "options"), null, CREDENTIAL_SET_QUERY_CLASS_NAME
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
                        CREDENTIAL_SET_QUERY_CLASS_NAME
                    )
                }
            }
        }
    }
}

sealed class ClaimValue {
    data class StringValue(val value: String) : ClaimValue()
    data class LongValue(val value: Long) : ClaimValue()
    data class BoolValue(val value: Boolean) : ClaimValue()

    companion object {
        fun from(value: Any?): ClaimValue {
            return when (value) {
                is Boolean -> BoolValue(value)
                is Int -> LongValue(value.toLong())
                is Long -> LongValue(value)
                is String -> StringValue(value)
                else -> throw OpenID4VPExceptions.InvalidData(
                    "Claim value must be a string, integer, or boolean",
                    CLAIM_VALUE_CLASS_NAME
                )
            }
        }
    }
}

data class ClaimsQuery(
    val id: String? = null,
    val path: List<Any?>,
    val values: List<ClaimValue>? = null
) {
    internal fun validate(isClaimSetsAvailable: Boolean) {
        if (isClaimSetsAvailable && id == null) {
            throw OpenID4VPExceptions.InvalidData(
                "Claims with claim_sets must have an id",
                CLAIMS_QUERY_CLASS_NAME
            )
        }

        id?.let {
            if (!VALID_ID_PATTERN.matches(it)) {
                throw OpenID4VPExceptions.InvalidData(
                    "Claims Query id must consist of alphanumeric, underscore or hyphen characters",
                    CLAIMS_QUERY_CLASS_NAME
                )
            }
        }

        if (path.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("claims_query", "path"), null, CLAIMS_QUERY_CLASS_NAME
            )
        }

        values?.let {
            if (it.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("claims_query", "values"), null, CLAIMS_QUERY_CLASS_NAME
                )
            }
        }
    }
}

private fun parseDcqlQuery(jsonObject: JsonObject): DCQLQuery {
    val credentials = jsonObject.requiredArray("credentials", listOf("dcql_query", "credentials"))
        .mapIndexed { index, credentialElement ->
            parseCredentialQuery(
                credentialElement.requireJsonObject(
                    listOf("dcql_query", "credentials", index.toString()),
                    DCQL_QUERY_CLASS_NAME
                )
            )
        }

    val credentialSets = jsonObject.optionalArray("credential_sets", listOf("dcql_query", "credential_sets"))
        ?.mapIndexed { index, credentialSetElement ->
            parseCredentialSetQuery(
                credentialSetElement.requireJsonObject(
                    listOf("dcql_query", "credential_sets", index.toString()),
                    DCQL_QUERY_CLASS_NAME
                )
            )
        }

    return DCQLQuery(credentials = credentials, credentialSets = credentialSets)
}

private fun parseCredentialQuery(jsonObject: JsonObject): CredentialQuery {
    val id = jsonObject.requiredString("id", listOf("credential_query", "id"), CREDENTIAL_QUERY_CLASS_NAME)
    val format = jsonObject.requiredString(
        "format",
        listOf("credential_query", "format"),
        CREDENTIAL_QUERY_CLASS_NAME
    )
    val multiple = jsonObject.optionalBoolean(
        "multiple",
        listOf("credential_query", "multiple"),
        CREDENTIAL_QUERY_CLASS_NAME
    ) ?: false
    val meta = jsonObject.optionalObject("meta", listOf("credential_query", "meta"), CREDENTIAL_QUERY_CLASS_NAME)
        ?.toDynamicMap() ?: emptyMap()
    val requireCryptographicHolderBinding = jsonObject.optionalBoolean(
        "require_cryptographic_holder_binding",
        listOf("credential_query", "require_cryptographic_holder_binding"),
        CREDENTIAL_QUERY_CLASS_NAME
    ) ?: true
    val claims = jsonObject.optionalArray("claims", listOf("credential_query", "claims"))
        ?.mapIndexed { index, claimElement ->
            parseClaimsQuery(
                claimElement.requireJsonObject(
                    listOf("credential_query", "claims", index.toString()),
                    CREDENTIAL_QUERY_CLASS_NAME
                )
            )
        }
    val claimSets = jsonObject.optionalArray("claim_sets", listOf("credential_query", "claim_sets"))
        ?.mapIndexed { index, claimSetElement ->
            claimSetElement.requireJsonArray(
                listOf("credential_query", "claim_sets", index.toString()),
                CREDENTIAL_QUERY_CLASS_NAME
            ).mapIndexed { nestedIndex, claimIdElement ->
                claimIdElement.requireJsonPrimitive(
                    listOf("credential_query", "claim_sets", index.toString(), nestedIndex.toString()),
                    CREDENTIAL_QUERY_CLASS_NAME,
                    expected = "String"
                ).content
            }
        }

    return CredentialQuery(
        id = id,
        format = format,
        multiple = multiple,
        meta = meta,
        requireCryptographicHolderBinding = requireCryptographicHolderBinding,
        claims = claims,
        claimSets = claimSets
    )
}

private fun parseClaimsQuery(jsonObject: JsonObject): ClaimsQuery {
    val id = jsonObject.optionalString("id", listOf("claims_query", "id"), CLAIMS_QUERY_CLASS_NAME)
    val path = jsonObject.requiredArray("path", listOf("claims_query", "path"))
        .map { pathEntry -> pathEntry.toDynamicValue() }
    val values = jsonObject.optionalArray("values", listOf("claims_query", "values"))
        ?.map { valueElement -> ClaimValue.from(valueElement.toDynamicValue()) }

    return ClaimsQuery(id = id, path = path, values = values)
}

private fun parseCredentialSetQuery(jsonObject: JsonObject): CredentialSetQuery {
    val options = jsonObject.requiredArray("options", listOf("credential_set_query", "options"))
        .mapIndexed { index, optionElement ->
            optionElement.requireJsonArray(
                listOf("credential_set_query", "options", index.toString()),
                CREDENTIAL_SET_QUERY_CLASS_NAME
            ).mapIndexed { nestedIndex, credentialIdElement ->
                credentialIdElement.requireJsonPrimitive(
                    listOf("credential_set_query", "options", index.toString(), nestedIndex.toString()),
                    CREDENTIAL_SET_QUERY_CLASS_NAME,
                    expected = "String"
                ).content
            }
        }
    val required = jsonObject.optionalBoolean(
        "required",
        listOf("credential_set_query", "required"),
        CREDENTIAL_SET_QUERY_CLASS_NAME
    ) ?: true

    return CredentialSetQuery(options = options, required = required)
}

private fun DCQLQuery.toJsonObject(): JsonObject = buildJsonObject {
    put("credentials", buildJsonArray {
        credentials.forEach { credential ->
            add(credential.toJsonObject())
        }
    })
    credentialSets?.let { sets ->
        put("credential_sets", buildJsonArray {
            sets.forEach { credentialSet ->
                add(credentialSet.toJsonObject())
            }
        })
    }
}

private fun CredentialQuery.toJsonObject(): JsonObject = buildJsonObject {
    put("id", JsonPrimitive(id))
    put("format", JsonPrimitive(format))
    put("meta", meta.toJsonObject())
    if (multiple) {
        put("multiple", JsonPrimitive(multiple))
    }
    if (!requireCryptographicHolderBinding) {
        put(
            "require_cryptographic_holder_binding",
            JsonPrimitive(requireCryptographicHolderBinding)
        )
    }
    claims?.let { claimQueries ->
        put("claims", buildJsonArray {
            claimQueries.forEach { claimQuery ->
                add(claimQuery.toJsonObject())
            }
        })
    }
    claimSets?.let { sets ->
        put("claim_sets", buildJsonArray {
            sets.forEach { claimSet ->
                add(buildJsonArray {
                    claimSet.forEach { claimId ->
                        add(JsonPrimitive(claimId))
                    }
                })
            }
        })
    }
}

private fun CredentialSetQuery.toJsonObject(): JsonObject = buildJsonObject {
    put("options", buildJsonArray {
        options.forEach { option ->
            add(buildJsonArray {
                option.forEach { credentialId ->
                    add(JsonPrimitive(credentialId))
                }
            })
        }
    })
    if (!required) {
        put("required", JsonPrimitive(required))
    }
}

private fun ClaimsQuery.toJsonObject(): JsonObject = buildJsonObject {
    id?.let { put("id", JsonPrimitive(it)) }
    put("path", JsonArray(path.map { it.toJsonElement(listOf("claims_query", "path")) }))
    values?.let { claimValues ->
        put("values", JsonArray(claimValues.map { it.toJsonElement() }))
    }
}

private fun ClaimValue.toJsonElement(): JsonElement = when (this) {
    is ClaimValue.StringValue -> JsonPrimitive(value)
    is ClaimValue.LongValue -> JsonPrimitive(value)
    is ClaimValue.BoolValue -> JsonPrimitive(value)
}

private fun Map<String, Any>.toJsonObject(): JsonObject = buildJsonObject {
    for ((key, value) in this@toJsonObject) {
        put(key, value.toJsonElement(listOf("credential_query", "meta", key)))
    }
}

private fun Any?.toJsonElement(fieldPath: List<String>): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Number -> JsonPrimitive(this)
    is Map<*, *> -> buildJsonObject {
        for ((key, value) in this@toJsonElement) {
            val stringKey = key as? String ?: throw OpenID4VPExceptions.JsonEncodingFailed(
                fieldPath,
                "Only string keys are supported while serializing dynamic JSON objects",
                DCQL_QUERY_CLASS_NAME
            )
            put(stringKey, value.toJsonElement(fieldPath + stringKey))
        }
    }
    is List<*> -> JsonArray(mapIndexed { index, value -> value.toJsonElement(fieldPath + index.toString()) })
    else -> throw OpenID4VPExceptions.JsonEncodingFailed(
        fieldPath,
        "Unsupported value type '${this::class.simpleName}' while serializing dcql_query",
        DCQL_QUERY_CLASS_NAME
    )
}

private fun JsonObject.requiredString(key: String, fieldPath: List<String>, className: String): String {
    val element = this[key] ?: throw OpenID4VPExceptions.MissingInput(fieldPath, "", className)
    return element.requireJsonPrimitive(fieldPath, className, expected = "String").content
}

private fun JsonObject.optionalString(key: String, fieldPath: List<String>, className: String): String? {
    val element = this[key] ?: return null
    return element.requireJsonPrimitive(fieldPath, className, expected = "String").content
}

private fun JsonObject.optionalBoolean(key: String, fieldPath: List<String>, className: String): Boolean? {
    val element = this[key] ?: return null
    return element.requireJsonPrimitive(fieldPath, className, expected = "Boolean").booleanOrNull
        ?: throw OpenID4VPExceptions.InvalidInput(fieldPath, "Boolean", className)
}

private fun JsonObject.requiredArray(key: String, fieldPath: List<String>): JsonArray {
    val element = this[key] ?: throw OpenID4VPExceptions.MissingInput(fieldPath, "", DCQL_QUERY_CLASS_NAME)
    return element.requireJsonArray(fieldPath, DCQL_QUERY_CLASS_NAME)
}

private fun JsonObject.optionalArray(key: String, fieldPath: List<String>): JsonArray? {
    val element = this[key] ?: return null
    return element.requireJsonArray(fieldPath, DCQL_QUERY_CLASS_NAME)
}

private fun JsonObject.optionalObject(key: String, fieldPath: List<String>, className: String): JsonObject? {
    val element = this[key] ?: return null
    return element.requireJsonObject(fieldPath, className)
}

private fun JsonElement.requireJsonObject(fieldPath: List<String>, className: String): JsonObject {
    return this as? JsonObject ?: throw OpenID4VPExceptions.InvalidInput(fieldPath, "map", className)
}

private fun JsonElement.requireJsonArray(fieldPath: List<String>, className: String): JsonArray {
    return this as? JsonArray ?: throw OpenID4VPExceptions.InvalidInput(fieldPath, null, className)
}

private fun JsonElement.requireJsonPrimitive(
    fieldPath: List<String>,
    className: String,
    expected: String
): JsonPrimitive {
    val primitive = this as? JsonPrimitive ?: throw OpenID4VPExceptions.InvalidInput(fieldPath, expected, className)
    if (primitive == JsonNull) {
        throw OpenID4VPExceptions.InvalidInput(fieldPath, expected, className)
    }
    if (expected == "String" && !primitive.isString) {
        throw OpenID4VPExceptions.InvalidInput(fieldPath, expected, className)
    }
    return primitive
}

private fun JsonObject.toDynamicMap(): Map<String, Any> = entries.associate { (key, value) ->
    key to (value.toDynamicValue() ?: JsonNull)
}

private fun JsonElement.toDynamicValue(): Any? = when (this) {
    JsonNull -> null
    is JsonPrimitive -> when {
        isString -> content
        booleanOrNull != null -> booleanOrNull
        intOrNull != null -> intOrNull
        longOrNull != null -> longOrNull
        floatOrNull != null -> floatOrNull
        doubleOrNull != null -> doubleOrNull
        else -> content
    }
    is JsonArray -> map { it.toDynamicValue() }
    is JsonObject -> entries.associate { (key, value) -> key to value.toDynamicValue() }
}
