package io.mosip.openID4VP.common

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.api.ExpansionApi
import com.apicatalog.jsonld.document.JsonDocument
import com.fasterxml.jackson.databind.ObjectMapper
import foundation.identity.jsonld.JsonLDObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import jakarta.json.Json
import jakarta.json.JsonArray
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JsonLDTest {

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `static expand should accept map input and return JsonArray with mocked layers`() {
        mockkStatic("io.mosip.openID4VP.common.UtilsKt")
        mockkStatic(JsonLDObject::class)
        mockkStatic(JsonLd::class)

        val mapper = mockk<ObjectMapper>()
        val jsonLdObject = mockk<JsonLDObject>()
        val expansionApi = mockk<ExpansionApi>()
        val expanded = Json.createArrayBuilder()
            .add(
                Json.createObjectBuilder()
                    .add("@id", "urn:test:1")
                    .add("http://schema.org/name", Json.createArrayBuilder().add("Bob"))
            )
            .build()

        every { getObjectMapper() } returns mapper
        every { mapper.writeValueAsString(any<Map<String, Any>>()) } returns "{}"
        every { JsonLDObject.fromMap(any<Map<String, Any>>()) } returns jsonLdObject
        every { jsonLdObject.documentLoader = any() } returns Unit
        every { jsonLdObject.toJsonObject() } returns Json.createObjectBuilder().add("name", "Bob").build()
        every { JsonLd.expand(any<JsonDocument>()) } returns expansionApi
        every { expansionApi.loader(any()) } returns expansionApi
        every { expansionApi.get() } returns expanded

        val inputMap = mapOf(
            "@context" to mapOf(
                "name" to "http://schema.org/name"
            ),
            "name" to "Bob"
        )

        val result = JsonLD.expand(inputMap)

        assertNotNull(result)
        assertTrue(result is JsonArray)
        assertFalse(result.isEmpty())
        verify(exactly = 1) { JsonLDObject.fromMap(any<Map<String, Any>>()) }
        verify(exactly = 1) { JsonLd.expand(any<JsonDocument>()) }
        verify(exactly = 1) { expansionApi.get() }
    }
}

