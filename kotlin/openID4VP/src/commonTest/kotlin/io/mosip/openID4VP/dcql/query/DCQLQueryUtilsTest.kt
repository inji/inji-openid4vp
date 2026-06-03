package io.mosip.openID4VP.dcql.query

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class `DCQLQueryUtilsTest` {

    @Test
    fun `should parse dcql query from json string`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to """
                {
                  "credentials": [
                    {"id": "cred1", "meta":{}, "format": "vc+sd-jwt", "claims": [{"path": ["given_name"]}]}
                  ]
                }
            """.trimIndent()
        )

        val result = parseAndValidateDcqlQuery(authorizationRequest)
        val query = assertIs<DCQLQuery>(result[AuthorizationRequestFieldConstants.DCQL_QUERY.value])

        assertEquals("cred1", query.credentials.first().id)
        assertEquals("vc+sd-jwt", query.credentials.first().format)
    }

    @Test
    fun `should parse dcql query from map`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to mapOf(
                "credentials" to listOf(
                    mapOf(
                        "id" to "cred1",
                        "format" to "mso_mdoc",
                        "meta" to mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                    )
                )
            )
        )

        val result = parseAndValidateDcqlQuery(authorizationRequest)
        val query = assertIs<DCQLQuery>(result[AuthorizationRequestFieldConstants.DCQL_QUERY.value])

        assertEquals(1, query.credentials.size)
        assertTrue(query.credentials.first().meta.containsKey("doctype_value"))
    }

    @Test
    fun `should parse claim path with array index`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to mapOf(
                "credentials" to listOf(
                    mapOf(
                        "id" to "employee-sd-jwt",
                        "format" to "vc+sd-jwt",
                        "meta" to emptyMap<String, Any>(),
                        "claims" to listOf(
                            mapOf("path" to listOf("degrees", 0, "type"))
                        )
                    )
                )
            )
        )

        val result = parseAndValidateDcqlQuery(authorizationRequest)
        val query = assertIs<DCQLQuery>(result[AuthorizationRequestFieldConstants.DCQL_QUERY.value])

        assertEquals(listOf("degrees", 0, "type"), query.credentials.first().claims?.first()?.path)
    }

    @Test
    fun `should throw when claim values contain nested arrays`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to """
                {
                  "credentials": [
                    {
                      "id": "tax-id",
                      "format": "vc+sd-jwt",
                      "meta": {},
                      "claims": [
                        {
                          "path": ["issuing_authority"],
                          "values": [["DE", "TelOrg"]]
                        }
                      ]
                    }
                  ]
                }
            """.trimIndent()
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(authorizationRequest)
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw missing input when dcql query field is absent`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(mutableMapOf())
        }

        assertOpenId4VPException(
            exception,
            "Missing Input: authorizationRequest->dcql_query param is required",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw invalid data when json is malformed`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to "{\"credentials\":["
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(authorizationRequest)
        }

        assertTrue(exception.message!!.startsWith("Failed to parse dcql_query:"))
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
    }
}
