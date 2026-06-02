package io.mosip.openID4VP.common

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.http.media.MediaType
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import jakarta.json.JsonArray


object JsonLDProcessor {
    private const val CLASS_NAME = "JsonLDProcessor"
    fun expand(input: Map<String, Any>): JsonArray {
        return try {
            val loader = getDocumentLoader()
            val jsonLdObject = JsonLDObject.fromMap(input)
            jsonLdObject.documentLoader = loader

            val jsonDocument = JsonDocument.of(MediaType.JSON_LD, jsonLdObject.toJsonObject())

            JsonLd.expand(jsonDocument).loader(loader).get()
        } catch (e: OpenID4VPExceptions) {
            throw e
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "JSON-LD expansion failed: ${e.message}",
                CLASS_NAME
            )
        }
    }

    fun getDocumentLoader(): ConfigurableDocumentLoader =
        ConfigurableDocumentLoader().apply {
            isEnableHttps = true
            isEnableHttp = true
            isEnableFile = false
        }
}
