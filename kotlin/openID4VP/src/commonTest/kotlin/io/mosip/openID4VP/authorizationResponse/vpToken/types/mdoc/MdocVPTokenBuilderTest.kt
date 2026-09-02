package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.ByteString
import io.mosip.openID4VP.common.decodeCbor
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.taggedCbor24
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class MdocVPTokenBuilderTest {

    private val builder = MdocVPTokenBuilder()
    private val credential = mdocCredential()
    private val signature = "signature-bytes".toByteArray(Charsets.UTF_8)

    @BeforeTest
    fun setUp() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg<ByteArray>())
        }
        mockkObject(MdocCredentialUtils)
        every {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(any(), any())
        } returns Pair("keyRef", "ES256")
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `builds an mdoc vp token keyed by credential query id`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "mobile-id")),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signature))
        )

        val token = assertIs<MdocVPToken>(result.getValue("mobile-id").single())
        assertTrue(token.base64EncodedDeviceResponse.isNotEmpty())
    }

    @Test
    fun `groups multiple mdoc credentials under the same credential query id`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(
                dcqlMapping("id-1", "mobile-id"),
                dcqlMapping("id-2", "mobile-id")
            ),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(id = "id-1", signedData = signature),
                VPTokenSigningResult(id = "id-2", signedData = signature)
            )
        )

        assertEquals(2, result.getValue("mobile-id").size)
    }

    @Test
    fun `creates one mdoc vp per credential each carrying a single document`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(
                dcqlMapping("id-1", "mobile-id"),
                dcqlMapping("id-2", "mobile-id")
            ),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(id = "id-1", signedData = signature),
                VPTokenSigningResult(id = "id-2", signedData = signature)
            )
        )

        val tokens = result.getValue("mobile-id")
        assertEquals(2, tokens.size)
        tokens.forEach { vpToken ->
            val deviceResponse = decodeCbor(
                Base64.getUrlDecoder().decode(assertIs<MdocVPToken>(vpToken).base64EncodedDeviceResponse)
            ) as CborMap
            val documents = deviceResponse.get(UnicodeString("documents")) as CborArray
            assertEquals(1, documents.dataItems.size)
        }
    }

    @Test
    fun `separates mdoc credentials across distinct credential query ids`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(
                dcqlMapping("id-1", "mobile-id"),
                dcqlMapping("id-2", "residence-id")
            ),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(id = "id-1", signedData = signature),
                VPTokenSigningResult(id = "id-2", signedData = signature)
            )
        )

        assertEquals(setOf("mobile-id", "residence-id"), result.keys)
    }

    @Test
    fun `rejects a dcql mdoc credential that is not a string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(
                    CredentialToCredentialQueryIdMapping(FormatType.MSO_MDOC, 42, "mobile-id")
                        .apply { identifier = "id-1" }
                ),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signature))
            )
        }
        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `requires a signing result for every dcql mdoc mapping`() {
        assertFailsWith<OpenID4VPExceptions.MissingInput> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "mobile-id")),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = emptyList()
            )
        }
    }

    @Test
    fun `rejects an unsupported signing algorithm when building the device signature`() {
        every {
            MdocCredentialUtils.extractMdocKeyReferenceAndAlg(any(), any())
        } returns Pair("keyRef", "HS256")

        assertFailsWith<IllegalArgumentException> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "mobile-id")),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signature))
            )
        }
    }

    private fun dcqlMapping(identifier: String, credentialQueryId: String) =
        CredentialToCredentialQueryIdMapping(FormatType.MSO_MDOC, credential, credentialQueryId)
            .apply { this.identifier = identifier }

    private fun mdocCredential(): String {
        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
        }
        val issuerAuth = CborArray().apply {
            add(ByteString(byteArrayOf()))
            add(CborMap())
            add(taggedCbor24(mso))
            add(ByteString(byteArrayOf()))
        }
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("nameSpaces"), CborMap())
                put(UnicodeString("issuerAuth"), issuerAuth)
            })
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encodeCbor(root))
    }
}
