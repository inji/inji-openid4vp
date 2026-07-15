package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class SdJwtVPTokenBuilderTest {

    private val builder = SdJwtVPTokenBuilder()
    private val credential = "header.payload.signature~disclosure~"
    private val unsignedKbJwt = "kbheader.kbpayload"
    private val signatureBytes = "kb-signature".toByteArray(Charsets.UTF_8)

    private lateinit var unsignedVPToken: UnsignedVPToken

    @BeforeTest
    fun setUp() {
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg<ByteArray>())
        }
        unsignedVPToken = UnsignedVPToken(
            id = "id-1",
            format = FormatType.VC_SD_JWT,
            holderKeyReference = "did:example:holder",
            signatureAlgorithm = "ES256",
            dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
        )
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `builds a key-bound sd-jwt keyed by credential query id`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
            unsignedVPTokenResult = Pair(mapOf("id-1" to unsignedKbJwt), listOf(unsignedVPToken)),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes))
        )

        val token = assertIs<SdJwtVPToken>(result.getValue("employee-card").single())
        assertEquals("$credential$unsignedKbJwt.${base64(signatureBytes)}", token.value)
    }

    @Test
    fun `returns the credential unchanged when no key binding jwt was prepared`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
            unsignedVPTokenResult = Pair(emptyMap(), listOf(unsignedVPToken)),
            vpTokenSigningResults = emptyList()
        )

        val token = assertIs<SdJwtVPToken>(result.getValue("employee-card").single())
        assertEquals(credential, token.value)
    }

    @Test
    fun `groups multiple sd-jwt credentials under the same credential query id`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(
                dcqlMapping("id-1", "employee-card"),
                dcqlMapping("id-2", "employee-card")
            ),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = emptyList()
        )

        assertEquals(2, result.getValue("employee-card").size)
    }

    @Test
    fun `requires an identifier on every dcql mapping`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(
                    CredentialToCredentialQueryIdMapping(FormatType.VC_SD_JWT, credential, "employee-card")
                ),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = emptyList()
            )
        }
        assertEquals(
            "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
            exception.message
        )
    }

    @Test
    fun `rejects a dcql sd-jwt credential that is not a string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(
                    CredentialToCredentialQueryIdMapping(FormatType.VC_SD_JWT, 42, "employee-card")
                        .apply { identifier = "id-1" }
                ),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = emptyList()
            )
        }
        assertEquals("SD-JWT credential is not a String", exception.message)
    }

    @Test
    fun `requires an identifier on every presentation exchange mapping`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, credential, "input-1")
                ),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }
        assertEquals(
            "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
            exception.message
        )
    }

    @Test
    fun `rejects a presentation exchange sd-jwt credential that is not a string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, 42, "input-1")
                        .apply { identifier = "id-1" }
                ),
                unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }
        assertEquals("SD-JWT credential is not a String", exception.message)
    }

    @Test
    fun `requires a signing result for a key-bound sd-jwt`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            builder.build(
                credentialInputDescriptorMappings = listOf(peMapping("id-1", "input-1")),
                unsignedVPTokenResult = Pair(mapOf("id-1" to unsignedKbJwt), listOf(unsignedVPToken)),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }
        assertEquals(
            "Missing VP token signing result for credential identifier id-1",
            exception.message
        )
    }

    @Test
    fun `rejects an empty signature for a key-bound sd-jwt`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            builder.build(
                credentialInputDescriptorMappings = listOf(peMapping("id-1", "input-1")),
                unsignedVPTokenResult = Pair(mapOf("id-1" to unsignedKbJwt), listOf(unsignedVPToken)),
                vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = ByteArray(0))),
                rootIndex = 0
            )
        }
        assertEquals("Invalid signature for identifier id-1", exception.message)
    }

    @Test
    fun `rejects duplicate signing results for the same identifier`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialInputDescriptorMappings = listOf(peMapping("id-1", "input-1")),
                unsignedVPTokenResult = Pair(mapOf("id-1" to unsignedKbJwt), listOf(unsignedVPToken)),
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(id = "id-1", signedData = signatureBytes),
                    VPTokenSigningResult(id = "id-1", signedData = signatureBytes)
                ),
                rootIndex = 0
            )
        }
        assertEquals("Duplicate VP token signing result for credential identifier id-1", exception.message)
    }

    @Test
    fun `advances the descriptor map index across mappings`() {
        val (tokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                peMapping("id-1", "input-1"),
                peMapping("id-2", "input-2")
            ),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = emptyList(),
            rootIndex = 2
        )

        assertEquals(2, tokens.size)
        assertEquals(listOf("$[2]", "$[3]"), descriptorMaps.map { it.path })
        assertEquals(listOf("input-1", "input-2"), descriptorMaps.map { it.id })
        assertEquals(4, nextIndex)
    }

    private fun base64(bytes: ByteArray) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun dcqlMapping(identifier: String, credentialQueryId: String) =
        CredentialToCredentialQueryIdMapping(FormatType.VC_SD_JWT, credential, credentialQueryId)
            .apply { this.identifier = identifier }

    private fun peMapping(identifier: String, inputDescriptorId: String) =
        CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, credential, inputDescriptorId)
            .apply { this.identifier = identifier }
}
