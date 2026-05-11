package io.mosip.openID4VP.evaluator.dcql

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.ClaimsQuery
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.CredentialQuery
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.DCQLQuery
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.wallet.Credential
import java.io.ByteArrayOutputStream
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DcqlEvaluatorTest {

    private val evaluator = DcqlEvaluator()

    @BeforeTest
    fun setUp() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            java.util.Base64.getUrlDecoder().decode(firstArg<String>())
        }
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should match sd-jwt credential by format and vct`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwtCredential(id = "sdjwt-1")))

        assertTrue(result.success)
        assertEquals(listOf("sdjwt-1"), result.queryMatches["employee-card"]?.matchingCredentials?.map { it.credentialId })
    }

    @Test
    fun `should match mdoc credential by doctype`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(mdocCredential("mdoc-1")))

        assertTrue(result.success)
        assertEquals("mdoc-1", result.queryMatches["mobile-id"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `should match claims by nested path`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "w3c-card",
                    format = FormatType.LDP_VC.value,
                    claims = listOf(
                        ClaimsQuery(id = "given-name", path = listOf("credentialSubject", "given_name"))
                    )
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(w3cCredential(id = "ldp-1")))

        assertTrue(result.success)
        assertEquals(1, result.queryMatches["w3c-card"]?.matchingCredentials?.first()?.matchingClaims?.size)
    }

    @Test
    fun `should return no matching credentials when wallet credentials do not satisfy query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwtCredential(id = "sdjwt-1", vct = "https://example.com/other"))
        )

        assertFalse(result.success)
        assertNull(result.queryMatches["employee-card"]?.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should return empty result when no credential matches requested format`() {
        val query = DCQLQuery(
            credentials = listOf(CredentialQuery(id = "employee-card", format = FormatType.VC_SD_JWT.value))
        )

        val result = evaluator.evaluate(query, listOf(mdocCredential("mdoc-1")))

        assertFalse(result.success)
        assertNull(result.queryMatches["employee-card"]?.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.NO_MATCHING_FORMATS_FOUND.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should return multiple matching credentials`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    multiple = true,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwtCredential(id = "sdjwt-1"), sdJwtCredential(id = "sdjwt-2"))
        )

        assertTrue(result.success)
        assertEquals(2, result.queryMatches["employee-card"]?.matchingCredentials?.size)
        assertTrue(result.queryMatches["employee-card"]?.allowMultipleCredentials == true)
    }

    private fun sdJwtCredential(
        id: String,
        format: FormatType = FormatType.VC_SD_JWT,
        vct: String = "https://example.com/employee",
        holderBinding: Boolean = true
    ): Credential {
        val payload = mutableMapOf<String, Any>(
            "vct" to vct,
            "issuing_country" to "DE",
            "issuance_date" to "2025-01-01",
            "given_name" to "Alice"
        )
        if (holderBinding) {
            payload["cnf"] = mapOf("kid" to "did:example:holder#key-1")
        }

        val objectMapper = getObjectMapper()
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString(objectMapper.writeValueAsBytes(mapOf("alg" to "none")))
        val encodedPayload = encoder.encodeToString(objectMapper.writeValueAsBytes(payload))

        return Credential(format = format, data = "$header.$encodedPayload.signature", credentialId = id)
    }

    private fun mdocCredential(id: String): Credential {
        val cborMap = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
        }
        val output = ByteArrayOutputStream()
        CborEncoder(output).encode(cborMap)

        return Credential(
            format = FormatType.MSO_MDOC,
            data = Base64.getUrlEncoder().withoutPadding().encodeToString(output.toByteArray()),
            credentialId = id
        )
    }

    private fun w3cCredential(id: String): Credential {
        val credentialSubject = mutableMapOf<String, Any>(
            "given_name" to "Alice",
            "family_name" to "Jones",
            "id" to "did:example:holder"
        )

        return Credential(
            format = FormatType.LDP_VC,
            data = mapOf(
                "type" to listOf("VerifiableCredential", "EmployeeCredential"),
                "credentialSubject" to credentialSubject
            ),
            credentialId = id
        )
    }
}
