package io.mosip.openID4VP.authorizationRequest.clientMetadata

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

class JwksSerializerTest {

    // https://github.com/inji/inji-wallet/issues/2524
    // Test: oid4vp-1final-wallet-ignores-unusable-encryption-key
    @Test
    fun `should ignore unusable jwks and keep only the usable encryption key`() {
        val json = """
            {
              "keys": [
                {
                  "kty": "OKP",
                  "use": "enc",
                  "crv": "X25519",
                  "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                  "alg": "ECDH-ES",
                  "kid": "valid-enc-key"
                },
                {
                  "kty": "AKP",
                  "alg": "ML-KEM-9999",
                  "use": "enc",
                  "kid": "post-quantum-key"
                },
                {
                  "kty": "OIDF-CONFORMANCE-UNSUPPORTED",
                  "use": "enc",
                  "kid": "unsupported-key"
                }
              ]
            }
        """.trimIndent()

        val jwks = Json.decodeFromString(JwksSerializer, json)

        assertEquals(1, jwks.keys.size)
        assertEquals("valid-enc-key", jwks.keys.first().kid)
    }

    @Test
    fun `should return empty keys when every key is unusable`() {
        val json = """
            { "keys": [ { "kty": "AKP", "alg": "ML-KEM-9999", "use": "enc", "kid": "pq-key" } ] }
        """.trimIndent()

        val jwks = Json.decodeFromString(JwksSerializer, json)

        assertEquals(0, jwks.keys.size)
    }

    @Test
    fun `should return empty keys when keys array is absent`() {
        val jwks = Json.decodeFromString(JwksSerializer, "{}")

        assertEquals(0, jwks.keys.size)
    }

    @Test
    fun `should return empty keys when keys is present but not an array`() {
        val jwks = Json.decodeFromString(JwksSerializer, """{ "keys": { "kty": "OKP" } }""")

        assertEquals(0, jwks.keys.size)
    }

    @Test
    fun `should ignore entries in keys array that are not json objects`() {
        val json = """
            {
              "keys": [
                "not-an-object",
                {
                  "kty": "OKP",
                  "use": "enc",
                  "crv": "X25519",
                  "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                  "alg": "ECDH-ES",
                  "kid": "valid-enc-key"
                }
              ]
            }
        """.trimIndent()

        val jwks = Json.decodeFromString(JwksSerializer, json)

        assertEquals(1, jwks.keys.size)
        assertEquals("valid-enc-key", jwks.keys.first().kid)
    }
}
