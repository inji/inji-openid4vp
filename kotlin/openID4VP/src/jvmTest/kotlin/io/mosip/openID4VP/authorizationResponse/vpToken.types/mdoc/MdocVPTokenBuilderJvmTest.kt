package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.Array
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mockk.*
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.resolveMdocKeyAndAlg
import io.mosip.openID4VP.testData.mdocCredential
import kotlin.test.*
import co.nstant.`in`.cbor.model.Map as CborMap

class MdocVPTokenBuilderJvmTest {

    private val docType = "org.iso.18013.5.1.mDL"

    @BeforeTest
    fun setUp() {
        mockkStatic(::resolveMdocKeyAndAlg)
        every { resolveMdocKeyAndAlg(any(), any()) } returns Pair("keyRef", "ES256")
        mockkStatic(::getDecodedMdocCredential)
        every { getDecodedMdocCredential(any()) } answers {
            val cred = firstArg<String>()
            val map = co.nstant.`in`.cbor.model.Map()
            // Use the credential to determine docType: first call returns mDL, second returns elc
            if (!cred.startsWith("om5")) { // mdocCredential from testData starts differently from encodeCbor output
                map.put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
            } else {
                map.put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.elc"))
            }
            map
        }
    }

    @Test
    fun `should decode base64 using JVM decoder`() {
        val input = "aGVsbG8=" // "hello"
        val decoded = decodeFromBase64Url(input)
        assertEquals("hello", decoded.toString(Charsets.UTF_8))

        val unsignedVPToken = UnsignedVPToken(
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuthBytes".toByteArray()
        )
        val vpTokenSigningResults = listOf(VPTokenSigningResult(signedData = "c2lnbmF0dXJlX2RhdGE=".toByteArray()))

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    "org.iso.18013.5.1.mDL"
                ).apply { identifier = docType }
            ),
            unsignedVPTokenResult = Pair(
                mapOf(docType to "deviceAuthentication"),
                listOf(unsignedVPToken)
            ),
            vpTokenSigningResults = vpTokenSigningResults,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)

        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as Map

        assertEquals("1.0", decodedCbor[UnicodeString("version")].toString())
        assertEquals(0, decodedCbor[UnicodeString("status")].toString().toInt())
        assertNotNull(decodedCbor[UnicodeString("documents")])
        assertEquals(1, descriptorMaps.size)
        assertEquals("[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null)]", descriptorMaps.toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should return token with multiple documents for multiple credentials`() {
        val mdocCredential2 = encodeCbor(
            cborMapOf(
                "docType" to "org.iso.18013.5.1.elc",
                "issuerSigned" to cborMapOf()
            )
        )

        val unsignedVPToken1 = UnsignedVPToken(
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth1".toByteArray()
        )
        val unsignedVPToken2 = UnsignedVPToken(
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth2".toByteArray()
        )
        val vpTokenSigningResults = listOf(
            VPTokenSigningResult(signedData = "c2lnbmF0dXJlX2RhdGE=".toByteArray()),
            VPTokenSigningResult(signedData = "c2lnbmF0dXJlX2RhdGE=".toByteArray())
        )

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    "org.iso.18013.5.1.mDL"
                ).apply { identifier = "org.iso.18013.5.1.mDL" },
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    encodeToBase64Url(mdocCredential2),
                    "org.iso.18013.5.1.elc"
                ).apply { identifier = "org.iso.18013.5.1.elc" }
            ),
            unsignedVPTokenResult = Pair(
                mapOf(
                    "org.iso.18013.5.1.elc" to "deviceAuthentication2",
                    "org.iso.18013.5.1.mDL" to "deviceAuthentication1"
                ),
                listOf(unsignedVPToken1, unsignedVPToken2)
            ),
            vpTokenSigningResults = vpTokenSigningResults,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)
        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        val documents = decodedCbor[UnicodeString("documents")] as Array
        assertNotNull(documents)
        assertTrue(documents.dataItems.size == 2)

        assertEquals(1, nextIndex)
        assertEquals("[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null), DescriptorMap(id=org.iso.18013.5.1.elc, format=mso_mdoc, path=\$[0], pathNested=null)]", descriptorMaps.toString())
    }

    @Test
    fun `should throw exception when device authentication signature is missing`() {
        val unsignedVPToken = UnsignedVPToken(
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth1".toByteArray()
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            MdocVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(
                        FormatType.MSO_MDOC,
                        mdocCredential,
                        "org.iso.18013.5.1.mDL"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                ),
                unsignedVPTokenResult = Pair(
                    mapOf("org.iso.18013.5.1.mDL" to "deviceAuthentication1"),
                    listOf(unsignedVPToken)
                ),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }

        assertEquals(
            "Device authentication signature not found for mdoc credential docType org.iso.18013.5.1.mDL",
            exception.message
        )
    }

    private fun mdocVPToken(vpTokens: List<MdocVPToken>): MdocVPToken {
        assertNotNull(vpTokens)
        assertTrue(vpTokens.size == 1)
        val vpToken = vpTokens.first() as MdocVPToken
        return vpToken
    }
}
