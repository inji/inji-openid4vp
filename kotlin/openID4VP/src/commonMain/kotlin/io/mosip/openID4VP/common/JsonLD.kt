package io.mosip.openID4VP.common

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.http.media.MediaType
import com.apicatalog.jsonld.loader.DocumentLoader
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import jakarta.json.JsonArray

private const val CLASS_NAME = "JsonLD"

/**
 * Wraps a JSON-LD document and provides JSON-LD processing operations such as
 * expansion.
 *
 * Usage:
 * ```kotlin
 * // Directly from map input
 * val expanded: JsonArray = JsonLD.expand(mapOf("@context" to "https://schema.org/", "name" to "Alice"))
 *
 * // Or via instance
 * val jsonLd = JsonLD.fromMap(mapOf("@context" to "https://schema.org/", "name" to "Alice"))
 * val expanded: JsonArray = jsonLd.expand()
 * ```
 */
class JsonLD private constructor(
    private val rawJson: String,
    private val jsonLdObject: JsonLDObject,
    private val documentLoader: DocumentLoader
) {

    companion object {
        /**
         * Shared JSON-LD document loader factory used across JSON-LD helpers.
         */
        fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
            val loader = ConfigurableDocumentLoader()
            loader.isEnableHttps = true
            loader.isEnableHttp = true
            loader.isEnableFile = false
            return loader
        }

        /**
         * Expands JSON-LD input represented as a map and returns the expanded JSON array.
         */
        fun expand(
            inputData: Map<String, Any>
        ): JsonArray {
            return fromMap(inputData).expand()
        }


        /**
         * Creates a [JsonLD] instance from a [Map] representing the JSON-LD document.
         * @return a [JsonLD] instance ready for processing
         * @throws [OpenID4VPExceptions.InvalidData] if the map cannot be serialized to JSON
         */
        private fun fromMap(
            map: Map<String, Any>,
        ): JsonLD {
            return try {
                val loader = getConfigurableDocumentLoader()
                val jsonString = getObjectMapper().writeValueAsString(map)
                val jsonLdObject = JsonLDObject.fromMap(map)
                jsonLdObject.documentLoader = loader
                JsonLD(jsonString, jsonLdObject, loader)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.InvalidData(
                    "Failed to serialize map to JSON-LD: ${e.message}",
                    CLASS_NAME
                )
            }
        }
    }

    /**
     * Expands the JSON-LD document by resolving all compact IRIs and context references.
     *
     * The expansion algorithm replaces JSON-LD term definitions and context shortcuts
     * with their fully-qualified IRI equivalents, producing a context-free representation
     * of the data that is safe to process without knowledge of the original contexts.
     *
     * @return expanded JSON-LD as [JsonArray]
     * @throws [OpenID4VPExceptions.InvalidData] if the document cannot be expanded
     */
    fun expand(): JsonArray {
        return try {
            // foundation JsonLDObject does not expose an expand() API; expansion is delegated
            // to titanium while preserving the configured document loader.
            val jakartaJsonObject = jsonLdObject.toJsonObject()
            val jsonDocument: JsonDocument = JsonDocument.of(MediaType.JSON_LD, jakartaJsonObject)

            val expandedArray: JsonArray = JsonLd
                .expand(jsonDocument)
                .loader(documentLoader)
                .get()

            expandedArray
        } catch (e: OpenID4VPExceptions) {
            throw e
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "JSON-LD expansion failed: ${e.message}",
                CLASS_NAME
            )
        }
    }


    override fun toString(): String = rawJson

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JsonLD) return false
        return rawJson == other.rawJson
    }

    override fun hashCode(): Int = rawJson.hashCode()
}



