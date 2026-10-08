package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.ResponseMode.DIRECT_POST_JWT
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import kotlinx.serialization.json.Json
import org.assertj.core.api.Assertions.assertThat
import kotlin.test.*
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.constants.ResponseMode
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.testData.presentationDefinitionMap
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class PresentationDefinitionTest {

    private lateinit var presentationDefinition: String
    private lateinit var expectedExceptionMessage: String

   @BeforeTest
   fun setUp() {
       mockkObject(NetworkManagerClient)
   }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should throw missing input exception if id param is missing`() {
        presentationDefinition =
            """{"input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage = "Missing Input: presentation_definition->id param is required"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.MissingInput> {
                deserializeAndValidate(
                    presentationDefinition,
                    PresentationDefinitionSerializer
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if input_descriptors param is missing`() {
        presentationDefinition = """{"id":"pd_123"}"""
        expectedExceptionMessage = "Missing Input: presentation_definition->input_descriptors param is required"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.MissingInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if id param value is empty`() {
        presentationDefinition =
            """{"id":"","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage =
            "Invalid Input: presentation_definition->id value cannot be an empty string, null, or an integer"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if input_descriptor param value is empty`() {
        presentationDefinition = """{"id":"pd_123","input_descriptors":[]}"""
        expectedExceptionMessage =
            "Invalid Input: presentation_definition->input_descriptors value cannot be empty or null"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if input_descriptor param value is present but it's value is null`() {
        presentationDefinition = """{"id":"pd_123","input_descriptors":null}"""
        expectedExceptionMessage =
            "Invalid Input: presentation_definition->input_descriptors value cannot be empty or null"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage,actualException.message)
    }

    @Test
    fun `should throw error if presentation definition uri is not supported by wallet`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val expectedExceptionMessage = "presentation_definition_uri is not supported"

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(authorizationRequestParam, false)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE, exception.errorCode)
        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error when presentation definition uri returned with non 2xx response`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        every { NetworkManagerClient.sendHTTPRequest(any(),any(), any(), any()) } returns NetworkResponse(400, """{"message":"error"}""", mapOf("Content-Type" to listOf("application/json")))

        val expectedExceptionMessage = "presentation_definition_uri could not be reached: https://mock-verifier.com/verifier/get-presentation-definition. Error: Error while fetching presentation_definition from presentation_definition_uri: https://mock-verifier.com/verifier/get-presentation-definition, status code: 400 with body: {\"message\":\"error\"}"

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(authorizationRequestParam, true)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI, exception.errorCode)
        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should serialize PresentationDefinition correctly with all fields`() {
        val presentationDefinition = PresentationDefinition(
            id = "test-id",
            inputDescriptors = listOf(
                InputDescriptor(
                    id = "descriptor-id",
                    name = "Test Descriptor",
                    purpose = "Testing",
                    constraints = Constraints(
                        fields = listOf(
                            Fields(
                                id = "id",
                                path = listOf("$.type"),
                                filter = Filter(type = "type", pattern = "pattern")
                            )
                        )
                    )
                )
            ),
            name = "Test Definition",
            purpose = "Unit Testing",
            format = mapOf(
                "mso_mdoc" to mapOf("alg" to listOf("EC")),
                "ldp_vc" to mapOf("proof_type" to listOf("Ed25519Signature2018"))
            )
        )

        val json = Json.encodeToString(PresentationDefinitionSerializer, presentationDefinition)
        val decodedPresentationDefinition = Json.decodeFromString(PresentationDefinitionSerializer, json)

        assertThat(decodedPresentationDefinition)
            .usingRecursiveComparison()
            .isEqualTo(presentationDefinition)
    }

    private val uri = "https://mock-verifier.com/verifier/get-presentation-definition"

    @Test
    fun `rejects supplying both presentation_definition and presentation_definition_uri`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(
                mutableMapOf(
                    PRESENTATION_DEFINITION.value to presentationDefinitionMap,
                    PRESENTATION_DEFINITION_URI.value to uri,
                    RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
                ),
                true
            )
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `rejects supplying neither presentation_definition nor presentation_definition_uri`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(
                mutableMapOf(RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value),
                true
            )
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Either presentation_definition or presentation_definition_uri request param must be present",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `rejects an invalid presentation_definition_uri`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(
                mutableMapOf(
                    PRESENTATION_DEFINITION_URI.value to "not-a-url",
                    RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
                ),
                true
            )
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "presentation_definition_uri is not valid",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI
        )
    }

    @Test
    fun `rejects a blank presentation_definition_uri response body`() {
        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns
            NetworkResponse(200, "   ", emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(uriRequest(), true)
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "presentation_definition_uri response body is not valid",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE
        )
    }

    @Test
    fun `rejects a presentation_definition_uri body that is not a presentation definition`() {
        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns
            NetworkResponse(200, """{"unexpected":"payload"}""", emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(uriRequest(), true)
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "presentation_definition_uri did not contain valid presentation_definition",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE
        )
    }

    @Test
    fun `resolves a presentation definition fetched from presentation_definition_uri`() {
        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns
            NetworkResponse(200, presentationDefinitionJson, emptyMap())

        val request = uriRequest()
        parseAndValidatePresentationDefinition(request, true)

        val resolved = assertIs<PresentationDefinition>(request[PRESENTATION_DEFINITION.value])
        assertEquals("649d581c-f891-4969-9cd5-2c27385a348f", resolved.id)
    }

    @Test
    fun `resolves a presentation definition supplied as a map`() {
        val request = mutableMapOf<String, Any>(
            PRESENTATION_DEFINITION.value to presentationDefinitionMap,
            RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
        )

        parseAndValidatePresentationDefinition(request, true)

        assertIs<PresentationDefinition>(request[PRESENTATION_DEFINITION.value])
    }

    @Test
    fun `resolves a presentation definition supplied as a json string`() {
        val request = mutableMapOf<String, Any>(
            PRESENTATION_DEFINITION.value to presentationDefinitionJson,
            RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
        )

        parseAndValidatePresentationDefinition(request, true)

        assertIs<PresentationDefinition>(request[PRESENTATION_DEFINITION.value])
    }

    @Test
    fun `accepts an already deserialized presentation definition`() {
        val existing = deserializeAndValidate(presentationDefinitionMap, PresentationDefinitionSerializer)
        val request = mutableMapOf<String, Any>(
            PRESENTATION_DEFINITION.value to existing,
            RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
        )

        parseAndValidatePresentationDefinition(request, true)

        assertEquals(existing, request[PRESENTATION_DEFINITION.value])
    }

    @Test
    fun `rejects a presentation_definition of an unsupported type`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(
                mutableMapOf(
                    PRESENTATION_DEFINITION.value to 42,
                    RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
                ),
                true
            )
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "presentation_definition must be of type String, Map, or PresentationDefinition",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `requires an encrypted response mode when an input descriptor requests mso_mdoc`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(
                mutableMapOf(
                    PRESENTATION_DEFINITION.value to msoMdocPresentationDefinition,
                    RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
                ),
                true
            )
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt or iar-post.jwt or iae_post.jwt",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `accepts mso_mdoc with encrypted response modes`() {
        listOf(ResponseMode.DIRECT_POST_JWT, ResponseMode.IAR_POST_JWT, ResponseMode.IAE_POST_JWT).forEach { responseMode ->
            val request = mutableMapOf<String, Any>(
                PRESENTATION_DEFINITION.value to msoMdocPresentationDefinition,
                RESPONSE_MODE.value to responseMode.value
            )

            parseAndValidatePresentationDefinition(request, true)

            assertIs<PresentationDefinition>(request[PRESENTATION_DEFINITION.value])
        }
    }

    @Test
    fun `accepts a non-mdoc presentation definition with a plain response mode`() {
        val request = mutableMapOf<String, Any>(
            PRESENTATION_DEFINITION.value to presentationDefinitionMap,
            RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
        )

        parseAndValidatePresentationDefinition(request, true)

        assertIs<PresentationDefinition>(request[PRESENTATION_DEFINITION.value])
    }

    private fun uriRequest() = mutableMapOf<String, Any>(
        PRESENTATION_DEFINITION_URI.value to uri,
        RESPONSE_MODE.value to ResponseMode.DIRECT_POST.value
    )

    private val presentationDefinitionJson = """
        {
          "id": "649d581c-f891-4969-9cd5-2c27385a348f",
          "input_descriptors": [
            {
              "id": "idcardcredential",
              "format": { "ldp_vc": { "proof_type": ["Ed25519Signature2018"] } },
              "constraints": { "fields": [ { "path": ["${'$'}.type"] } ] }
            }
          ]
        }
    """.trimIndent()

    private val msoMdocPresentationDefinition = mapOf(
        "id" to "mdoc-request",
        "input_descriptors" to listOf(
            mapOf(
                "id" to "mobile-id",
                "format" to mapOf("mso_mdoc" to mapOf("alg" to listOf("ES256"))),
                "constraints" to mapOf(
                    "fields" to listOf(mapOf("path" to listOf("${'$'}.type")))
                )
            )
        )
    )
}
