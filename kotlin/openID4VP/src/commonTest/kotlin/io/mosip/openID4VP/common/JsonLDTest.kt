package io.mosip.openID4VP.common

import jakarta.json.JsonArray
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JsonLDTest {

    // A minimal self-contained JSON-LD document that does not require remote context fetching
    private val inlineContextJson = """
        {
          "@context": {
            "name": "http://schema.org/name",
            "homepage": {"@id": "http://schema.org/url", "@type": "@id"}
          },
          "name": "Alice",
          "homepage": "https://alice.example.com"
        }
    """.trimIndent()

    // JSON-LD with a common W3C credentials context (remote, loaded over HTTPS)
    private val w3cCredentialJson = """
        {
          "@context": [
            "https://www.w3.org/2018/credentials/v1"
          ],
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "alumniOf": {
              "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
              "name": "Example University"
            }
          }
        }
    """.trimIndent()

    @Test
    fun `static expand should accept map input and return JsonArray`() {
        val inputMap = mapOf(
            "@context" to mapOf(
                "name" to "http://schema.org/name"
            ),
            "name" to "Bob"
        )

        val expanded = JsonLD.expand(inputMap)

        assertNotNull(expanded)
        assertTrue(expanded is JsonArray)
        assertFalse(expanded.isEmpty())
    }
}

