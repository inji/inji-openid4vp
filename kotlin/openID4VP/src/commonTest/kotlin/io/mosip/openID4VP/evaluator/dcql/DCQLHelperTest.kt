package io.mosip.openID4VP.evaluator.dcql

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.CredentialQuery
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.CredentialSetQuery
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
import kotlin.test.assertTrue

class DCQLHelperTest {

    private val helper = DCQLHelper()

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
    fun `should get matching credentials`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = helper.getMatchingCredentials(listOf(sdJwtCredential("sdjwt-1")), query)

        assertTrue(result.success)
        assertEquals("sdjwt-1", result.queryMatches["employee-card"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `should return no helper matches when credentials do not satisfy query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(sdJwtCredential("sdjwt-1", vct = "https://example.com/other")),
            query
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should satisfy required credential set when option is fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                ),
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf("employee-card", "mobile-id")))
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(sdJwtCredential("sdjwt-1"), mdocCredential("mdoc-1")),
            query
        )

        assertTrue(result.success)
        assertEquals(1, result.credentialSets.size)
        assertEquals(2, result.queryMatches.size)
    }

    private fun sdJwtCredential(id: String, vct: String = "https://example.com/employee"): Credential {
        val objectMapper = getObjectMapper()
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString(objectMapper.writeValueAsBytes(mapOf("alg" to "none")))
        val payload = encoder.encodeToString(
            objectMapper.writeValueAsBytes(
                mapOf(
                    "vct" to vct,
                    "cnf" to mapOf("kid" to "did:example:holder#key-1"),
                    "issuing_country" to "DE"
                )
            )
        )
        return Credential(FormatType.VC_SD_JWT, "$header.$payload.signature", id)
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
}
