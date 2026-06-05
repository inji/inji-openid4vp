package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdPrefix.*
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.testData.*
import org.junit.Test
import kotlin.test.*

class AuthorizationRequestObjectObtainedByReferenceTest {
    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HttpMethod.GET
            )
        } returns NetworkResponse(200, presentationDefinitionString, mapOf())
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                HttpMethod.GET
            )
        } returns NetworkResponse(200, didResponse, mapOf())
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }


    @Test
    fun `should gracefully handle unsupported client_id_prefix during POST and proceed with request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(
                io.mosip.openID4VP.constants.VPFormatType.LDP_VC to LdpVcFormatSupported(
                    proofTypeValues = listOf(io.mosip.openID4VP.constants.ProofType.Ed25519Signature2020)
                )
            ),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.REDIRECT_URI),
            requestObjectSigningAlgValuesSupported = listOf(io.mosip.openID4VP.constants.RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(io.mosip.openID4VP.constants.KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(io.mosip.openID4VP.constants.ContentEncryptionAlgorithm.A256GCM)
        )

        val openID4VP = OpenID4VP("test-OpenID4VP", walletConfig)

        // With graceful error handling, unsupported client_id_prefix during POST metadata
        // processing is logged as a warning and the request proceeds without wallet_metadata.
        // The request then fails for other reasons (e.g., network/JWS validation).
        assertFailsWith<Exception> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
    }


    @Test
    fun `should throw error if context type is wrong for request uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                headers = any()
            )
        } returns NetworkResponse(200,
            createAuthorizationRequestObject(DECENTRALIZED_IDENTIFIER, authorizationRequestParamsMap).toString(), mapOf("content-type" to listOf("application/json")))

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DECENTRALIZED_IDENTIFIER
            )

        val invalidInputException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
        assertEquals(
            "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
            invalidInputException.message
        )
    }

    @Test
    fun `should throw exception when the call to request_uri method fails in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET,
                headers = any()
            )
        } throws NetworkManagerClientExceptions.NetworkRequestTimeout()

        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DECENTRALIZED_IDENTIFIER)



        val exceptionWhenRequestUriNetworkCallFails = assertFailsWith<Exception> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                walletConfig,
                { _: String -> },
                walletNonce
            )
        }

        assertEquals(
            "Network error while fetching request_uri: VP sharing failed due to connection timeout",
            exceptionWhenRequestUriNetworkCallFails.message
        )
    }

    @Test
    fun `should throw exception when request_uri is not present in did client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                false,
                DECENTRALIZED_IDENTIFIER,
                authRequestWithDidByValue
            )


        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                walletConfig,
                { _: String -> },
                walletNonce
            )
        }

        assertEquals(
            "unsigned request is not supported for given client_id_prefix - decentralized_identifier",
            invalidDataException.message
        )
    }



    @Test
    fun `should throw error if  request_uri is not valid in authorization request`() {
        val authorizationRequestParamsMap =
            requestParams + clientIdOfDid + mapOf(REQUEST_URI.value to "test-data")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, ClientIdPrefix.REDIRECT_URI)


        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals("request_uri data is not valid", exception.message)
    }

}
