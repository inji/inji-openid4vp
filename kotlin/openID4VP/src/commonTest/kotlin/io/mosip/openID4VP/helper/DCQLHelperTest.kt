package io.mosip.openID4VP.helper

import co.nstant.`in`.cbor.model.DataItem
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.common.MdocCredentialUtils.getMdocDocType
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.evaluator.DCQLEvaluationErrorCodes
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.CredentialSetQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.dcql.evaluator.DCQLTestFixtures
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DCQLHelperTest {

    private val helper = DCQLHelper()

    @BeforeTest
    fun setUp() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }

        mockkStatic(::decodeCbor)
        every { decodeCbor(any())} returns  DCQLTestFixtures.getDecodedMdoc()

        mockkObject(MdocCredentialUtils)
        every { getMdocDocType(any<Any>(), any()) } returns "org.iso.18013.5.1.mDL"
        every { getMdocDocType(any<DataItem>(), any()) } returns "org.iso.18013.5.1.mDL"
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should get matching credentials for single query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = helper.getMatchingCredentials(listOf(DCQLTestFixtures.sdJwtCredential("sdjwt-1")), query)

        assertTrue(result.success)
        assertEquals(
            "sdjwt-1",
            result.queryMatches["employee-card"]?.matchingCredentials?.first()?.credentialId
        )
    }

    @Test
    fun `should return failure when credentials do not satisfy query`() {
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
            listOf(DCQLTestFixtures.sdJwtCredential("sdjwt-1", vct = "https://example.com/other")),
            query
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should satisfy required credential set when all options are fulfilled`() {
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
            listOf(
                DCQLTestFixtures.sdJwtCredential("sdjwt-1"),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            ),
            query
        )

        assertTrue(result.success)
        assertEquals(1, result.credentialSets.size)
        assertEquals(2, result.queryMatches.size)
    }

    @Test
    fun `should fail when required credential set option is not fulfilled`() {
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
            listOf(DCQLTestFixtures.sdJwtCredential("sdjwt-1")),
            query
        )

        assertFalse(result.success)
    }

    @Test
    fun `should synthesize one required credential set per query when credentialSets is null`() {
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
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.sdJwtCredential("sdjwt-1"),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            ),
            query
        )

        assertEquals(2, result.credentialSets.size)
        assertEquals(listOf(listOf("employee-card")), result.credentialSets[0].options)
        assertTrue(result.credentialSets[0].required)
        assertEquals(listOf(listOf("mobile-id")), result.credentialSets[1].options)
        assertTrue(result.credentialSets[1].required)
    }

    @Test
    fun `should succeed when optional credential set is not fulfilled`() {
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
                CredentialSetQuery(
                    options = listOf(listOf("employee-card", "mobile-id")),
                    required = false
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential("sdjwt-1")),
            query
        )

        assertTrue(result.success)
    }
}