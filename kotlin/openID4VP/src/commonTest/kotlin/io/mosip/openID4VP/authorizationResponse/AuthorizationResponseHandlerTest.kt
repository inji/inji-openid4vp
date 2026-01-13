package io.mosip.openID4VP.authorizationResponse

import foundation.identity.jsonld.JsonLDObject
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.FormatType.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.testData.*
import java.io.IOException
import kotlin.collections.mapOf
import kotlin.test.*

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(ldpCredential1, ldpCredential2)
    private val ldpVcList2 = listOf(ldpCredential2)
    private val mdocVcList = listOf(mdocCredential)

    private val selectedLdpVcCredentialsList = mapOf(
        "456" to mapOf(LDP_VC to ldpVcList1),
        "789" to mapOf(LDP_VC to ldpVcList2)
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(MSO_MDOC to mdocVcList)
    )

    private val selectedSdJwtCredentialsList = mapOf(
        "142" to mapOf(VC_SD_JWT to listOf(sdJwtCredential1))
    )
    private val credentialsMap = mapOf(
        "input1" to mapOf(LDP_VC to listOf(ldpCredential1)),
        "input2" to mapOf(MSO_MDOC to listOf(mdocCredential))
    )

    private val credentialMap2 = mapOf(
        "input1" to mapOf(LDP_VC to listOf(ldpCredential1, ldpCredential2)),
        "input2" to mapOf(MSO_MDOC to listOf(mdocCredential)),
        "input3" to mapOf(VC_SD_JWT to listOf(sdJwtCredential1, sdJwtCredential2))
    )

    private val unsignedKBJwt = "eyJhbGciOiJFUzI1NksifQ.eyJub25jZSI6Im5vbmNlIn0"

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private val mockResponseHandler = mockk<ResponseModeBasedHandler>()

    @BeforeTest
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()

        mockkConstructor(LdpVPTokenBuilder::class)
        every {
            anyConstructed<LdpVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(ldpVPToken), listOf(
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[0]")
                ),
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[1]")
                )
            ),
            2
        )

        mockkConstructor(MdocVPTokenBuilder::class)
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(), 0
        )

        setField(
            authorizationResponseHandler,
            "formatToCredentialInputDescriptorMapping",
            mapOf(
                LDP_VC to listOf(
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential1, "456"),
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential2, "789"),
                )
            ) + mapOf(
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocVcList.first(),
                        "123"
                    )
                )
            )
        )
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                LDP_VC to Pair(vpTokenSigningPayload, unsignedLdpVPToken),
                MSO_MDOC to Pair(null, unsignedMdocVPToken),
            )
        )
        setField(authorizationResponseHandler, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")


        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(URDNA2015Canonicalization)
        mockkStatic(JsonLDObject::class)

        every { URDNA2015Canonicalization.canonicalize(any()) } returns "base64EncodedCanonicalisedData"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns "2024-02-13T10:00:00Z"

        mockkObject(NetworkManagerClient)

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any()) } returns Pair(
            vpTokenSigningPayload, unsignedLdpVPToken
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedMdocVPToken,
        )

        mockkConstructor(UnsignedSdJwtVPTokenBuilder::class)
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedSdJwtVPToken,
        )
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedSdJwtVPToken,
        )

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler
        every {
            mockResponseHandler.sendAuthorizationResponse(
                any(),
                any(),
                any(),
                any()
            )
        } returns NetworkResponse(200, "{\"message\":\"success\"}", mapOf())
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {
        val expectedUnsignedVPToken = mapOf(
            LDP_VC to unsignedLdpVPToken,
            MSO_MDOC to unsignedMdocVPToken,
        )

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedMdocCredentialsList + selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(unsignedVPToken)
        assertEquals(2, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[LDP_VC], unsignedVPToken[LDP_VC])
        assertEquals(
            expectedUnsignedVPToken[MSO_MDOC],
            unsignedVPToken[MSO_MDOC]
        )
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC, MSO_MDOC, SD_JWT formats`() {

        val expectedUnsignedVPToken = mapOf(
            LDP_VC to unsignedLdpVPToken,
            MSO_MDOC to unsignedMdocVPToken,
            VC_SD_JWT to unsignedSdJwtVPToken
        )
        val authRequest = authorizationRequest.copy()
        authRequest.presentationDefinition = deserializeAndValidate(
            presentationDefinitionMapWithSdJwt,
            PresentationDefinitionSerializer
        )
        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedMdocCredentialsList + selectedLdpVcCredentialsList + selectedSdJwtCredentialsList,
            holderId = holderId,
            authorizationRequest = authRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(unsignedVPToken)
        assertEquals(3, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[LDP_VC], unsignedVPToken[LDP_VC])
        assertEquals(expectedUnsignedVPToken[VC_SD_JWT], unsignedVPToken[VC_SD_JWT])
        assertEquals(
            expectedUnsignedVPToken[MSO_MDOC],
            unsignedVPToken[MSO_MDOC]
        )
    }

    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = mapOf(),
                holderId = holderId,
                authorizationRequest = authorizationRequest,
                responseUri = "https://mock-verifier.com",
                signatureSuite = signatureSuite,
                nonce = walletNonce
            )
        }
        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `should throw error when response type is not supported`() {
        val request = authorizationRequest.copy(responseType = "code")
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = request,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = authorizationRequest.responseUri!!
            )
        }
        assertEquals("Provided response_type - code is not supported", exception.message)
    }

    @Test
    fun `should throw error when a credential format entry is not available in unsignedVPTokens but available in vpTokenSigningResults`() {
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            emptyMap<FormatType, Pair<Any?, UnsignedVPToken>>()
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = authorizationRequest.responseUri!!
            )
        }

        assertEquals(
            "VPTokenSigningResult not provided for the required formats",
            exception.message
        )
    }

    @Test
    fun `should throw exception when credentials map is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = emptyMap(),
                holderId = holderId,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl,
                signatureSuite = signatureSuite,
                nonce = walletNonce
            )
        }

        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `should successfully share VP with valid signing results`() {
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                LDP_VC to ldpVPTokenSigningResult,
                MSO_MDOC to mdocVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        assertEquals("{\"message\":\"success\"}", result.additionalParams)

        verify {
            ResponseModeBasedHandlerFactory.get("direct_post")
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUrl,
                authorizationResponse = any(),
                walletNonce = any()
            )
        }
    }

    @Test
    fun `should throw exception when response type is not supported`() {
        val mockInvalidRequest = mockk<AuthorizationRequest>()
        every { mockInvalidRequest.responseType } returns "code"

        // Populate internal state with valid input first
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockInvalidRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Provided response_type - code is not supported", exception.message)
    }


    @Test
    fun `should throw exception when unsupported response mode is provided`() {
        val request = authorizationRequest.copy(responseMode = "unsupported_mode")
        every { ResponseModeBasedHandlerFactory.get("unsupported_mode") } throws
                InvalidData("Unsupported response mode: unsupported_mode", "")

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = request,
                vpTokenSigningResults = ldpvpTokenSigningResults + mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Unsupported response mode: unsupported_mode", exception.message)
    }

    @Test
    fun `should throw exception when unsupported response type is provided`() {
        // Create a mock AuthorizationRequest with an unsupported response type
        val mockRequestWithUnsupportedType = mockk<AuthorizationRequest>()
        every { mockRequestWithUnsupportedType.responseType } returns "invalid_vp_token"

        // Populate internal state with valid request first
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockRequestWithUnsupportedType,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "Provided response_type - invalid_vp_token is not supported",
            exception.message
        )
    }

    @Test
    fun `should throw exception when format in signing results not found in unsigned tokens`() {
        val ldpOnly = mapOf("input1" to mapOf(LDP_VC to listOf(ldpCredential1)))
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = ldpOnly,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "VPTokenSigningResult not provided for the required formats",
            exception.message
        )
    }

    @Test
    fun `should throw exception when network error occurs during response sending`() {
        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any())
        } throws IOException("Network connection failed")

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<IOException> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults + mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Network connection failed", exception.message)
    }

    @Test
    fun `should ignore empty credential lists for input descriptors`() {
        val input = mapOf(
            "input1" to mapOf(LDP_VC to listOf(ldpCredential1)),
            "input2" to mapOf(LDP_VC to emptyList())
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = input,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertEquals(1, result.size)
        assertEquals(unsignedLdpVPToken, result[LDP_VC])
    }

    @Test
    fun `constructUnsignedVPTokenV1 should successfully construct unsigned VP token`() {
        val verifiableCredentials = mapOf(
            "input1" to listOf(encodeToJsonString(ldpCredential1, "ldpCredential1", "LDP_VC")),
            "input2" to listOf(encodeToJsonString(ldpCredential2, "ldpCredential2", "LDP_VC"))
        )

        val result = authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = verifiableCredentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        assertNotNull(result)
        assertTrue(result.contains("verifiableCredential"))
        assertTrue(result.contains("type"))
    }

    @Test
    fun `constructUnsignedVPTokenV1 should throw exception when credentials map is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials = emptyMap(),
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `shareVPV1 should successfully share VP and return response`() {
        val vpResponseMetadata = VPResponseMetadata(
            publicKey = "did:example:123#key-1",
            jws = jws,
            domain = "example.com",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        val credentials = mapOf(
            "input1" to listOf(encodeToJsonString(ldpCredential1, "ldpCredential1", "LDP_VC")),
            "input2" to listOf(encodeToJsonString(ldpCredential2, "ldpCredential2", "LDP_VC"))
        )
        every {
            mockResponseHandler.sendAuthorizationResponse(
                any(),
                any(),
                any(),
                any()
            )
        } returns NetworkResponse(200, "{\"message\":\"successfully received verifiable presentation\",\"redirect_uri\":\"https://mock.com/redirect#response_code=12334==\"}", mapOf())

        authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = credentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        val result = authorizationResponseHandler.shareVPV1(
            vpResponseMetadata = vpResponseMetadata,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        assertEquals("{\"message\":\"successfully received verifiable presentation\",\"redirect_uri\":\"https://mock.com/redirect#response_code=12334==\"}", result)

        verify {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUrl,
                authorizationResponse = any(),
                walletNonce = any()
            )
        }
    }

    @Test
    fun `shareVPV1 should throw exception when VP response metadata is invalid`() {
        val mockVPResponseMetadata = mockk<VPResponseMetadata>()
        every { mockVPResponseMetadata.publicKey } returns ""
        every { mockVPResponseMetadata.jws } returns jws
        every { mockVPResponseMetadata.validate() } throws InvalidData(
            "Public key cannot be empty",
            ""
        )

        val credentials = mapOf(
            "input1" to listOf(
                encodeToJsonString(
                    ldpCredential1,
                    "ldpCredential1",
                    "LDP_VC"
                )
            )
        )

        authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = credentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVPV1(
                vpResponseMetadata = mockVPResponseMetadata,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl
            )
        }

        assertEquals("Public key cannot be empty", exception.message)
    }

    @Test
    fun `shareVPV1 should handle network errors during sharing`() {
        val vpResponseMetadata = VPResponseMetadata(
            publicKey = "did:example:123#key-1",
            jws = jws,
            domain = "example.com",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        val credentials = mapOf(
            "input1" to listOf(
                encodeToJsonString(
                    ldpCredential1,
                    "ldpCredential1",
                    "LDP_VC"
                )
            )
        )

        authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = credentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any())
        } throws IOException("Network connection failed")

        val exception = assertFailsWith<IOException> {
            authorizationResponseHandler.shareVPV1(
                vpResponseMetadata = vpResponseMetadata,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl
            )
        }

        assertEquals("Network connection failed", exception.message)
    }


    @Test
    fun ` wallet nonce is different for every construct unsignedVPToken call`() {
        val verifiableCredentials = mapOf(
            "input_descriptor1" to mapOf(
                LDP_VC to listOf(ldpCredential1)
            )
        )
        // First call
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = verifiableCredentials,
            holderId = "holder-id",
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = "JsonWebSignature2020",
            nonce = walletNonce
        )

        // Get the nonce from the first call using reflection
        val walletNonceField =
            AuthorizationResponseHandler::class.java.getDeclaredField("walletNonce")
        walletNonceField.isAccessible = true
        val firstNonce = walletNonceField.get(authorizationResponseHandler) as String

        // Second call
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = verifiableCredentials,
            holderId = "holder- id",
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = "JsonWebSignature2020",
            nonce = walletNonce
        )

        val secondNonce = walletNonceField.get(authorizationResponseHandler) as String

        assertNotEquals(
            "Wallet nonce should be different for every constructUnsignedVPTokenV1 call",
            firstNonce,
            secondNonce
        )
    }

    @Test
    fun `should successfully construct unsigned VP token for SD-JWT`() {
        val sdJwtVcList = listOf(sdJwtCredential1, sdJwtCredential2)
        val sdJwtCredentialMap = mapOf("sdjwt-input" to mapOf(VC_SD_JWT to sdJwtVcList))

        mockkConstructor(UnsignedSdJwtVPTokenBuilder::class)
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any()) } returns Pair(
            null,
            UnsignedSdJwtVPToken(
                mapOf(
                    "uuid-1" to unsignedKBJwt,
                    "uuid-2" to "mock-unsigned-kb-jwt"
                )
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = sdJwtCredentialMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.containsKey(VC_SD_JWT))
        assertEquals(
            UnsignedSdJwtVPToken(
                mapOf(
                    "uuid-1" to unsignedKBJwt,
                    "uuid-2" to "mock-unsigned-kb-jwt"
                )
            ), result[VC_SD_JWT]
        )
    }

    @Test
    fun `should share SD-JWT VP successfully`() {
        val mockSigningResult = mockk<SdJwtVPTokenSigningResult>(relaxed = true)
        every { mockSigningResult.uuidToKbJWTSignature } returns mapOf("uuid-1" to "mock-signature")
        val mockUnsignedSdJwtVPToken = UnsignedSdJwtVPToken(
            uuidToUnsignedKBT = mapOf("uuid-1" to "mock-kb-jwt")
        )
        val mockVpTokenSigningPayload = mapOf("uuid-1" to sdJwtCredential1)

        mapOf(
            "unsignedVPToken" to mockUnsignedSdJwtVPToken,
            "vpTokenSigningPayload" to mockVpTokenSigningPayload
        )
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            mapOf(VC_SD_JWT to Pair(null, mockUnsignedSdJwtVPToken))
        )
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "sdjwt-input"
                    ).apply { identifier = "uuid-1" }
                )
            ))

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest.copy(responseType = "vp_token"),
            vpTokenSigningResults = mapOf(VC_SD_JWT to mockSigningResult),
            responseUri = responseUrl
        )

        assertEquals("{\"message\":\"success\"}", result.additionalParams)


        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = any(),
                url = eq(responseUrl),
                authorizationResponse = any(),
                walletNonce = any()
            )
        }

    }

    @Test
    fun `should throw if SD-JWT format not found in unsigned tokens during shareVP`() {
        val mockSigningResult = mockk<SdJwtVPTokenSigningResult>(relaxed = true)

        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            emptyMap<FormatType, Pair<VPTokenSigningPayload?, UnsignedVPToken>>()
        )

        assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest.copy(responseType = "vp_token"),
                mapOf(VC_SD_JWT to mockSigningResult),
                responseUrl
            )
        }
    }

    @Test
    fun `should share 2 SD-JWT credentials successfully`() {
        val sdJwt = UnsignedSdJwtVPToken(
            mapOf("uuid-1" to "kbjwt1", "uuid-2" to "kbjwt2")
        )

        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "142"
                    ).apply { identifier = "uuid-1" },
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential2,
                        "143"
                    ).apply { identifier = "uuid-2" }
                )
            ))
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                VC_SD_JWT to Pair(null, sdJwt)
            )
        )

        val signingResult = mockk<SdJwtVPTokenSigningResult>(relaxed = true)
        every { signingResult.uuidToKbJWTSignature } returns mapOf(
            "uuid-1" to "mock-signature",
            "uuid-2" to "mock-signature2"
        )
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest.copy(responseType = "vp_token"),
            mapOf(VC_SD_JWT to signingResult),
            responseUrl
        )

        assertEquals("{\"message\":\"success\"}", result.additionalParams)
    }

    @Test
    fun `should share 1 VC with vpToken as element and presentation submission correctly for vp_token response type`() {
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(
                DescriptorMap("input2", "mdoc_vp", "$[0]", null),
            ), 1
        )
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialMap2,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocCredential,
                        "input2"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                )
            )
        )

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                LDP_VC to ldpVPTokenSigningResult,
                MSO_MDOC to mdocVPTokenSigningResult,
                VC_SD_JWT to sdJwtVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        // assert if mockResponseHandler is called with correct authorization response
        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = any(),
                url = eq(responseUrl),
                authorizationResponse = match {
                    // Note: If only one vp token is being shared then tha path in the presentation submission takes value as $ and VP token is an element only and not array
                    assertEquals(
                        "VPTokenElement(value=MdocVPToken(base64EncodedDeviceResponse=base64EncodedDeviceResponse))",
                        it.vpToken.toString()
                    )
                    assertEquals(
                        "PresentationSubmission(id=649d581c-f291-4969-9cd5-2c27385a348f, definitionId=649d581c-f891-4969-9cd5-2c27385a348f, descriptorMap=[DescriptorMap(id=input2, format=mdoc_vp, path=$, pathNested=null)])",
                        it.presentationSubmission.toString()
                    )
                    it.presentationSubmission.descriptorMap.size == 1
                },
                walletNonce = any()
            )
        }
    }

// sharing of multiple credentials of different formats

    @Test
    fun `should share credentials for 2LDP, 2SD-JWT and 2MSO-MDOC VC`() {
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any()) } returns Pair(
            vpTokenSigningPayload2,
            unsignedLdpVPToken
        )
        every {
            anyConstructed<LdpVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(ldpVPToken2), listOf(
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[0]")
                ),
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[1]")
                )
            ), 2
        )
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(
                DescriptorMap("input2", "mdoc_vp", "$[3]", null),
            ), 4
        )


        val unsignedtokens = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialMap2,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )
        print(unsignedtokens)
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                LDP_VC to listOf(
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential1, "input1"),
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential2, "input1")
                ),
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocCredential,
                        "input2"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                ),
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "input3"
                    ).apply { identifier = "123" },
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential2,
                        "input3"
                    ).apply { identifier = "456" }
                )
            )
        )

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                LDP_VC to ldpVPTokenSigningResult,
                MSO_MDOC to mdocVPTokenSigningResult,
                VC_SD_JWT to sdJwtVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        assertEquals("{\"message\":\"success\"}", result.additionalParams)
        // assert if mockResponseHandler is called with correct authorization response
        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = any(),
                url = eq(responseUrl),
                authorizationResponse = match {
                    // Note: If only more than vp token is being shared then the path in presentation submission takes value as $[<index>] and VP token is an array holding all tokens together
                    assertEquals(
                        """
                    PresentationSubmission(id=649d581c-f291-4969-9cd5-2c27385a348f, definitionId=649d581c-f891-4969-9cd5-2c27385a348f, descriptorMap=[DescriptorMap(id=input1, format=ldp_vp, path=$[2], pathNested=PathNested(id=input1, format=ldp_vc, path=$.verifiableCredential[0])), DescriptorMap(id=input1, format=ldp_vp, path=$[2], pathNested=PathNested(id=input1, format=ldp_vc, path=$.verifiableCredential[1])), DescriptorMap(id=input2, format=mdoc_vp, path=$[3], pathNested=null), DescriptorMap(id=input3, format=vc+sd-jwt, path=$[4], pathNested=null), DescriptorMap(id=input3, format=vc+sd-jwt, path=$[5], pathNested=null)])
                        """.trimIndent(), it.presentationSubmission.toString()
                    )
                    true
                },
                walletNonce = any()
            )
        }
    }


    // Tests for sendAuthorizationError

// Tests for sendAuthorizationError

    @Test
    fun `sendAuthorizationError should send OpenID4VPExceptions payload including state`() {
        val bodySlot = slot<Map<String, String>>()
        val headersSlot = slot<Map<String, String>>()
        every {
            NetworkManagerClient.sendHTTPRequest(
                url = any(),
                method = any(),
                bodyParams = capture(bodySlot),
                headers = capture(headersSlot)
            )
        } returns NetworkResponse(400, "mock-error-response", mapOf())

        val ex = InvalidData("Some invalid data", "TestClass")
        val result = authorizationResponseHandler.sendAuthorizationError(
            responseUri = "https://verifier.example.com/cb",
            authorizationRequest = authorizationRequest,
            exception = ex
        )

        assertEquals("mock-error-response", result.additionalParams)
        assertTrue(bodySlot.isCaptured)
        assertEquals(authorizationRequest.state, bodySlot.captured["state"])
        assertTrue(headersSlot.captured["Content-Type"]!!.contains("application/x-www-form-urlencoded"))
    }

    @Test
    fun `sendAuthorizationError should wrap generic exception`() {
        val bodySlot = slot<Map<String, String>>()
        every {
            NetworkManagerClient.sendHTTPRequest(
                url = any(),
                method = any(),
                bodyParams = capture(bodySlot),
                headers = any()
            )
        } returns NetworkResponse(500, "\"message\":\"generic-error-response\"", mapOf())

        val ex = RuntimeException("Boom")
        val result = authorizationResponseHandler.sendAuthorizationError(
            responseUri = "https://verifier.example.com/cb",
            authorizationRequest = authorizationRequest,
            exception = ex
        )

        assertEquals("\"message\":\"generic-error-response\"", result.additionalParams)
        assertTrue(bodySlot.captured.containsKey("error"))
        assertTrue(bodySlot.captured.values.any { it.contains("Boom") })
    }

    @Test
    fun `sendAuthorizationError should throw when responseUri is null`() {
        val ex = InvalidData("msg", "Test")
        assertFailsWith<ErrorDispatchFailure> {
            authorizationResponseHandler.sendAuthorizationError(
                responseUri = null,
                authorizationRequest = authorizationRequest,
                exception = ex
            )
        }
    }

    @Test
    fun `sendAuthorizationError should throw ErrorDispatchFailure when network fails`() {
        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } throws RuntimeException("network down")

        val ex = InvalidData("msg", "Test")
        val failure = assertFailsWith<ErrorDispatchFailure> {
            authorizationResponseHandler.sendAuthorizationError(
                responseUri = "https://verifier.example.com/cb",
                authorizationRequest = authorizationRequest,
                exception = ex
            )
        }
        assertTrue(failure.message.contains("network down"))
    }


    @Test
    fun `constructAuthorizationErrorResponse should handle OpenID4VPExceptions`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "invalid_request", "error_description" to "Invalid data provided")

        val exception = InvalidData("Invalid data provided", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "invalid_request", "error_description" to "Invalid data provided"), result)

        verify {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        }
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle AccessDenied exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "access_denied")

        val exception = AccessDenied("Access denied to resource", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "access_denied"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle InvalidVerifier exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "invalid_client")

        val exception = InvalidVerifier("Invalid verifier provided", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "invalid_client"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle generic exceptions as GenericFailure`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "server_error")

        val genericException = RuntimeException("Unexpected runtime error")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = genericException,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "server_error"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle exception with null message`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "server_error")

        val exceptionWithNullMessage = RuntimeException(null as String?)

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exceptionWithNullMessage,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "server_error"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should preserve state from authorization request`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedErrorResponse = slot<AuthorizationErrorResponse>()
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = capture(capturedErrorResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("state" to "preserved")

        val exception = InvalidData("Test error", "TestClass")

        authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(authorizationRequest.state, capturedErrorResponse.captured.state)
    }

    @Test
    fun `constructAuthorizationErrorResponse should work with different response modes`() {
        val jwtRequest = authorizationRequestForResponseModeJWT

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post.jwt") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("jwt" to "encrypted_response")

        val exception = InvalidTransactionData("Invalid transaction", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = jwtRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("jwt" to "encrypted_response"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle MissingInput exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "invalid_request")

        val exception = MissingInput(
            "presentation_definition",
            "Missing required field: presentation_definition",
            "TestClass"
        )

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "invalid_request"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle InvalidInputPattern exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "invalid_request")

        val exception = InvalidInputPattern(listOf("path", "to", "field"), "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "invalid_request"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle JsonEncodingFailed exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("error" to "invalid_request")

        val exception = JsonEncodingFailed("fieldPath", "JSON encoding error", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest = authorizationRequest,
            exception = exception,
            walletNonce = "wallet-nonce-value"
        )

        assertEquals(mapOf("error" to "invalid_request"), result)
    }

    // Tests for constructAuthorizationResponse

    @Test
    fun `constructAuthorizationResponse should successfully construct response with valid inputs`() {
        // Setup mocks
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("response" to "finalized", "state" to authorizationRequest.state!!)

        // Setup internal state first
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        val result = authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        assertEquals(mapOf("response" to "finalized", "state" to authorizationRequest.state!!), result)

        verify {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = any<AuthorizationResponse>(),
                walletNonce = any<String>()
            )
        }
    }

    @Test
    fun `constructAuthorizationResponse should handle multiple format types`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = capture(capturedResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("multi_format" to "response")

        // Setup internal state with multiple formats
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList + selectedMdocCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult,
            MSO_MDOC to mdocVPTokenSigningResult
        )

        val result = authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        assertEquals(mapOf("multi_format" to "response"), result)
        assertNotNull(capturedResponse.captured.presentationSubmission)
        assertNotNull(capturedResponse.captured.vpToken)
        assertEquals(authorizationRequest.state, capturedResponse.captured.state)
    }

    @Test
    fun `constructAuthorizationResponse should handle different response modes`() {
        val jwtRequest = authorizationRequestForResponseModeJWT

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post.jwt") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = any<AuthorizationRequest>(),
                authorizationResponse = any<AuthorizationResponse>(),
                walletNonce = any<String>()
            )
        } returns mapOf("encrypted" to "jwt_response")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = jwtRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        val result = authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = jwtRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        assertEquals(mapOf("encrypted" to "jwt_response"), result)
    }

    @Test
    fun `constructAuthorizationResponse should throw error for unsupported response type`() {
        val invalidRequest = authorizationRequest.copy(responseType = "invalid_response_type")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest, // Use original for setup
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructAuthorizationResponse(
                authorizationRequest = invalidRequest,
                vpTokenSigningResults = vpTokenSigningResults
            )
        }

        assertTrue(exception.message!!.contains("invalid_response_type"))
        assertTrue(exception.message!!.contains("not supported"))
    }

    @Test
    fun `constructAuthorizationResponse should throw error when vpTokenSigningResults is missing formats`() {
        // Setup internal state with multiple formats
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList + selectedMdocCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        // Provide only partial signing results (missing MSO_MDOC)
        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
            // Missing MSO_MDOC signing result
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = vpTokenSigningResults
            )
        }

        assertTrue(exception.message!!.contains("VPTokenSigningResult not provided"))
    }

    @Test
    fun `constructAuthorizationResponse should preserve state from authorization request`() {
        val requestWithState = authorizationRequest.copy(state = "test-state-value")

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = requestWithState,
                authorizationResponse = capture(capturedResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("state" to "test-state-value")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = requestWithState,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = requestWithState,
            vpTokenSigningResults = vpTokenSigningResults
        )

        assertEquals("test-state-value", capturedResponse.captured.state)
    }

    @Test
    fun `constructAuthorizationResponse should handle null state in authorization request`() {
        val requestWithNullState = authorizationRequest.copy(state = null)

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = requestWithNullState,
                authorizationResponse = capture(capturedResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("response" to "no_state")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = requestWithNullState,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = requestWithNullState,
            vpTokenSigningResults = vpTokenSigningResults
        )

        assertNull(capturedResponse.captured.state)
    }

    @Test
    fun `constructAuthorizationResponse should create single VP token element when one format`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = capture(capturedResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("single" to "vp_token")

        // Setup internal state with single format
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        // Verify that vpToken is a VPTokenElement (single token) not VPTokenArray
        assertTrue(capturedResponse.captured.vpToken is VPTokenType.VPTokenElement)
    }

    @Test
    fun `constructAuthorizationResponse should create VP token array when multiple formats`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = capture(capturedResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("multiple" to "vp_tokens")

        // Setup internal state with multiple formats
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList + selectedMdocCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult,
            MSO_MDOC to mdocVPTokenSigningResult
        )

        authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        // Verify that vpToken is a VPTokenArray (multiple tokens)
        assertTrue(capturedResponse.captured.vpToken is VPTokenType.VPTokenArray)
    }

    @Test
    fun `constructAuthorizationResponse should generate valid presentation submission`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                authorizationResponse = capture(capturedResponse),
                walletNonce = any<String>()
            )
        } returns mapOf("presentation" to "submission")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val vpTokenSigningResults = mapOf(
            LDP_VC to ldpVPTokenSigningResult
        )

        authorizationResponseHandler.constructAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        val presentationSubmission = capturedResponse.captured.presentationSubmission
        assertNotNull(presentationSubmission.id)
        assertEquals(authorizationRequest.presentationDefinition.id, presentationSubmission.definitionId)
        assertTrue(presentationSubmission.descriptorMap.isNotEmpty())
    }


}
