package io.mosip.openID4VP.authorizationRequest.dcqlQuery

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DCQLQueryTest {

    @Test
    fun `should create valid query with single credential query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = "vc+sd-jwt",
                    claims = listOf(ClaimsQuery(path = listOf("given_name")))
                )
            )
        )

        assertEquals(1, query.credentials.size)
        assertEquals("employee-card", query.credentials.first().id)
        assertNull(query.credentialSets)
    }

    @Test
    fun `should create valid query with multiple credential queries`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "sdjwt", format = "vc+sd-jwt"),
                CredentialQuery(id = "mdoc", format = "mso_mdoc", multiple = true)
            )
        )

        assertEquals(2, query.credentials.size)
        assertTrue(query.credentials.last().multiple)
    }

    @Test
    fun `should create valid query with credential sets`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "sdjwt", format = "vc+sd-jwt"),
                CredentialQuery(id = "mdoc", format = "mso_mdoc")
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf("sdjwt"), listOf("mdoc")))
            )
        )

        assertNotNull(query.credentialSets)
        assertEquals(1, query.credentialSets.size)
        assertTrue(query.credentialSets.first().required)
    }

    @Test
    fun `should throw when credentials list is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(credentials = emptyList())
        }

        assertOpenId4VPException(
            exception,
            "Invalid Input: dcql_query->credentials value cannot be empty or null",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw when credential query ids are duplicated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(id = "duplicate", format = "vc+sd-jwt"),
                    CredentialQuery(id = "duplicate", format = "mso_mdoc")
                )
            )
        }

        assertOpenId4VPException(
            exception,
            "Credential Query ids must be unique within dcql_query",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw when credential set references unknown query id`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(CredentialQuery(id = "known", format = "vc+sd-jwt")),
                credentialSets = listOf(CredentialSetQuery(options = listOf(listOf("unknown"))))
            )
        }

        assertOpenId4VPException(
            exception,
            "credential_sets references unknown credential id 'unknown'",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should validate claims query with valid path components`() {
        val claimsQuery = ClaimsQuery(
            id = "degree",
            path = listOf("credentialSubject", "degrees", null, 0),
            values = listOf(ClaimValue.StringValue("Bachelor"))
        )

        claimsQuery.validate(isClaimSetsAvailable = true)

        assertEquals(4, claimsQuery.path.size)
        assertFalse(claimsQuery.values.isNullOrEmpty())
    }

    @Test
    fun `should throw when claims query path is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            ClaimsQuery(path = emptyList()).validate(isClaimSetsAvailable = false)
        }

        assertOpenId4VPException(
            exception,
            "Invalid Input: claims_query->path value cannot be empty or null",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `ClaimValue from should return StringValue for string input`() {
        val result = ClaimValue.from("hello")

        assertEquals(ClaimValue.StringValue("hello"), result)
    }

    @Test
    fun `ClaimValue from should return LongValue for int input`() {
        val result = ClaimValue.from(42)

        assertEquals(ClaimValue.LongValue(42L), result)
    }

    @Test
    fun `ClaimValue from should return LongValue for long input`() {
        val result = ClaimValue.from(100L)

        assertEquals(ClaimValue.LongValue(100L), result)
    }

    @Test
    fun `ClaimValue from should return BoolValue for true boolean input`() {
        val result = ClaimValue.from(true)

        assertEquals(ClaimValue.BoolValue(true), result)
    }

    @Test
    fun `ClaimValue from should return BoolValue for false boolean input`() {
        val result = ClaimValue.from(false)

        assertEquals(ClaimValue.BoolValue(false), result)
    }

    @Test
    fun `ClaimValue from should throw for null input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClaimValue.from(null)
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `ClaimValue from should throw for unsupported type input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClaimValue.from(listOf("unsupported"))
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }
}
