package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt

import io.mockk.unmockkAll
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.testData.presentationDefinitionMap
import kotlin.test.assertNull

class UnsignedSdJwtVPTokenBuilderJvmTest {

    private val clientId = "test-client"
    private val nonce = "test-nonce"

    private val testAuthorizationRequest: AuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(
            presentationDefinitionMap,
            PresentationDefinitionSerializer
        ),
        responseUri = "https://mock-verifier.com/response",
        redirectUri = null,
        nonce = nonce,
        state = null,
        walletNonce = null,
    )

    private val sdJwt2 =
        "eyJ4NXQjUzI1NiI6IjVlN3dXZGdicTZZQWNoT2l5VnBQbF9zRVBwc2Jtb2ZaMkVIbHJLN1pnQ0EiLCJ4NWMiOlsiTUlJQzJqQ0NBY0tnQXdJQkFnSUlDazg1UDVPa1RUOHdEUVlKS29aSWh2Y05BUUVMQlFBd2dZc3hDekFKQmdOVkJBWVRBa2xPTVFzd0NRWURWUVFJREFKTFFURVNNQkFHQTFVRUJ3d0pRa0ZPUjBGTVQxSkZNUTR3REFZRFZRUUtEQVZKU1VsVVFqRVhNQlVHQTFVRUN3d09SVmhCVFZCTVJTMURSVTVVUlZJeE1qQXdCZ05WQkFNTUtYZDNkeTVsZUdGdGNHeGxMbU52YlNBb1EwVlNWRWxHV1Y5V1ExOVRTVWRPWDBWRU1qVTFNVGtwTUI0WERUSTFNRE13TnpBMk5UQTFOVm9YRFRJNE1ETXdOakEyTlRBMU5Wb3dnWVl4Q3pBSkJnTlZCQVlUQWtsT01Rc3dDUVlEVlFRSURBSkxRVEVTTUJBR0ExVUVCd3dKUWtGT1IwRk1UMUpGTVE0d0RBWURWUVFLREFWSlNVbFVRakVYTUJVR0ExVUVDd3dPUlZoQlRWQk1SUzFEUlU1VVJWSXhMVEFyQmdOVkJBTU1KRU5GVWxSSlJsbGZWa05mVTBsSFRsOUZSREkxTlRFNUxVVkVNalUxTVRsZlUwbEhUakFxTUFVR0F5dGxjQU1oQVBuVTNianU5MGkxSlBScmE4eURHRGVWR0M5SGl0NkY4dEh6L1FIM0JpMWFvejh3UFRBTUJnTlZIUk1CQWY4RUFqQUFNQjBHQTFVZERnUVdCQlFlZ3krZCtoMWdhOTZFVGN1amtrYVF5SzNjeWpBT0JnTlZIUThCQWY4RUJBTUNCU0F3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUNwUGFrSjI5TlBrQXJKNy9id3l3NmVRa1RsQ09oWktucEpIY0dBbXBBblRaME96Q1RMNE5vNml5dFBONTRQLzdNdEIydUEwRVJ1bjhVc0UyZ3pBZEZPQWRUYXpNNnFjd1VNMzI1VmkzNkxOZGdlSlRiRTdaTm9LbEc5SDNEMlE4REg5SFEreVN2cUtId2VZY0RLdk9yRkMxWENva01JNTUvNUdPZXNGeXJYWTBQRDFuUnlubWtxbE95eVBUMUxqMzVEeFE1c3Y3a0dKS21oRzNoS2t1R2xFcFVYWkhham5qM0tFSjlLZm9ZOW83cVBGVUFJZGw2cDU1YmV6b2VPUzFGUDRCQlZvRllUZWNWR3B0SEk2Q1phUWthRHBzTjRmMCtrZjlTa2RpeW4yMkFQWkU2Z3dvTnQvSzVudEhDTmUxdUVGNlNRN1gxYlhRdk5HSDRadmdVTT0iLCJNSUlEeXpDQ0FyT2dBd0lCQWdJSXp0aFBrU3hmRXlrd0RRWUpLb1pJaHZjTkFRRUxCUUF3ZURFTE1Ba0dBMVVFQmhNQ1NVNHhDekFKQmdOVkJBZ01Ba3RCTVJJd0VBWURWUVFIREFsQ1FVNUhRVXhQVWtVeERqQU1CZ05WQkFvTUJVbEpTVlJDTVJjd0ZRWURWUVFMREE1RldFRk5VRXhGTFVORlRsUkZVakVmTUIwR0ExVUVBd3dXZDNkM0xtVjRZVzF3YkdVdVkyOXRJQ2hTVDA5VUtUQWVGdzB5TlRBek1EY3dOalV3TlRKYUZ3MHlPREF6TURZd05qVXdOVEphTUlHTE1Rc3dDUVlEVlFRR0V3SkpUakVMTUFrR0ExVUVDQXdDUzBFeEVqQVFCZ05WQkFjTUNVSkJUa2RCVEU5U1JURU9NQXdHQTFVRUNnd0ZTVWxKVkVJeEZ6QVZCZ05WQkFzTURrVllRVTFRVEVVdFEwVk9WRVZTTVRJd01BWURWUVFERENsM2QzY3VaWGhoYlhCc1pTNWpiMjBnS0VORlVsUkpSbGxmVmtOZlUwbEhUbDlGUkRJMU5URTVLVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFQUWV4aCsyZTBTSWRyN3IyUnNaS3dybEFGNTQ0cUZuMmQ2TVplQS9CbEtxZUtRVVZmZ0tEMjQ1S0lYWU1MYi9yMGNJY1hjOXYvdUlDR1VZbXozN3MzQTdJWEV2QllYSkd5dWlPRXI5dnZZeVl2U3N5a2IxRnlma3B3cXpyQytjbkZGcWU4UW1nOFI2WjVTSTAyWEh4NEliMGJzYVJDOHE4dER1TUtranQ0TjZ6enQ0Z053c083SjBEMDVqa3FqcG9tUytIdUVPQ01UMGlFMzRVd3lhWitXZW8rSE1yRktkREFISWhoL25FNnROUGMxaHBPaFYxK25obGFDR1RnWnhPNW51RkpqQWRjY2xsd2E2WEpKT1kreSswdUsxSFIvVEJ1QlB6T1RYWFgvTnBqSVhkSHZrTUxYTWFsRW92dXovWWxuVXE1WE15N2pOTUpJYlpwUVZwMGNDQXdFQUFhTkZNRU13RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVTZTYlJYNnRCWDVnMjg0T3hSSjJ3UXM1QVNLa3dEZ1lEVlIwUEFRSC9CQVFEQWdLRU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQkVraE9tODJkbVUxYUFDSXF4UElhUk96d0hGT3l6ZWowa3U2K0Zmb0FhdG9hR0t5QytXc2srcU8rSkdwblA3a04wdGh2bThjc0VvQTg4dW5ON21CMzVTSFJHOTVYOWZJYmZTZktta3RVbW0xcFJxN2xvMTdPZ3NYNWRYeEVDM05YMStYNjZBWTU4enhjcDgwMk1YOG92THM2YTRDcmhMd01oTUxNemJLWVRLVmp0MWxweDdhUlpzeFc4Zjkva0paL3MyOHBZUitpMUJYUXpWYWh1T0hzL2VLVmlqR1NkNFhmSXJ2cjdIUHNjUUE1VDgvU1M3VUhDWjY0Qjc5RENwZGozQkpNWmdpVVJiUzZEK0tYUm56SmR6UitzVVpRbmZDNm1wbE1IVzBRZURYOWpBa3A5MVdscHlYcFR1bWo2SFRYdUltVGF2aVQ1SUVEb2RudmlSa2hCIiwiTUlJRHR6Q0NBcCtnQXdJQkFnSUlDVFJEM1NPbUY2UXdEUVlKS29aSWh2Y05BUUVMQlFBd2VERUxNQWtHQTFVRUJoTUNTVTR4Q3pBSkJnTlZCQWdNQWt0Qk1SSXdFQVlEVlFRSERBbENRVTVIUVV4UFVrVXhEakFNQmdOVkJBb01CVWxKU1ZSQ01SY3dGUVlEVlFRTERBNUZXRUZOVUV4RkxVTkZUbFJGVWpFZk1CMEdBMVVFQXd3V2QzZDNMbVY0WVcxd2JHVXVZMjl0SUNoU1QwOVVLVEFlRncweU5ERXhNVGd3TkRJMU1UVmFGdzB6TWpFeE1UWXdOREkxTVRWYU1IZ3hDekFKQmdOVkJBWVRBa2xPTVFzd0NRWURWUVFJREFKTFFURVNNQkFHQTFVRUJ3d0pRa0ZPUjBGTVQxSkZNUTR3REFZRFZRUUtEQVZKU1VsVVFqRVhNQlVHQTFVRUN3d09SVmhCVFZCTVJTMURSVTVVUlZJeEh6QWRCZ05WQkFNTUZuZDNkeTVsZUdGdGNHeGxMbU52YlNBb1VrOVBWQ2t3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREhidDM1QTAyV1ZuMlJaNkRBekF3MDAyZ1Z5ajRGZWlHT2VMdFdhL3I0VERiTVpZMFlKNGJlUmhLcjNOWnJibm54SDhsSFJmUThaTkhHNVRxT1lyTzk3MjR2VU9QTlVNd293YmhpdzRKTU84U0JuK0JxNlpuRDBHYWN4SGMyRGJmakI4NFRzTU1UNkRIc0t2cmI0Z0pXMEVnMHRUMUdQZzc4NnN3NUtkNk1xYlZYQTNpOWM0WXgyU0s2TUh5U2FHcVRkazBCeWNvVi9VRVdCYXFwK0RuQ01IQlhCd2gySDRQYTlXR3JRSW1sRTZ5VjQ2R0g5bEFyYkVCVW9reWFyVjBHQmpuVHQ5YVZpak9YaVJ0QUE3bEwzR00zZVRBQ0dDUXJlME9kZDlKVUV5b2Iycmt4OU95TmFGK0dDL1l5Y0xBMDA4bU0zWFE1aTdKU093cVBrREpUQWdNQkFBR2pSVEJETUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFJd0hRWURWUjBPQkJZRUZOMXJNTjJ1YTJibnFBeWREU3FJYi9sbFBoYXRNQTRHQTFVZER3RUIvd1FFQXdJQ2hEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFBcXFFV3h5UUk3VlZjRCtadnA1U2RBNDlTNW84SGtzYW5mV1NBWVpJU3Jxd1RaRDlJS0ZyTndnTkhpUXB0Y2FpNDVpMG8yc0FUcjNtbGI0SFkvdklCSjlMYm1XWGJVbEthRGE0RlBGcWhBT1AxOEFIWS83N0p6QWpHWlNQN1VtaGdJeEV2ci9GOXFVRDROV045ME1zeGszcGs3TFhoWnl5dk9yaDBVOW5qb0FEaHhHb2hFQy85WDFiR3d2bWNnYmozNGtlZXZMUmNrU0E1a0dsOVd1N3BqRXZsbUs0M0s2Q1VwTkFNME1BWFBUby9salNReXZkTkN4QjNMRjV5OU9SWk0vakRmZjAyUVVvSmJYQVFqc1FTVzBKMWd5bUk2MWxKU1I3aUtSaU1TTHAzaHhnYmVxZ0dTR050Z1c3bHhqUXdJWGRMbTltUGU3QXBPSUNwRzZLV0E9PSJdLCJraWQiOiIyMnV3S09pMlU1RVhWMkhxOFZtR0JRU3NnUFRSRGRjMmRtUHdqSUtOdkcwIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRWREU0EifQ.eyJnZW5kZXIiOlt7Imxhbmd1YWdlIjoiZW5nIiwidmFsdWUiOiJmZW1hbGUifSx7Imxhbmd1YWdlIjoiZnJhIiwidmFsdWUiOiJmZU3DomxlIn0seyJsYW5ndWFnZSI6ImFyYSIsInZhbHVlIjoi2LDZg9ixIn1dLCJ2Y3QiOiJTRF9KV1QiLCJwb3N0YWxDb2RlIjoiNDUwMDkiLCJpc3MiOiJodHRwczovL2luamljZXJ0aWZ5LW1vY2sucWEtaW5qaTEubW9zaXAubmV0IiwiZnVsbE5hbWUiOnsiX3NkIjpbImZBMTQtRDZjOHhTSHFueGFPajVtNUlZUDlLelExRG1TSXRkQVFIaW5BVHciXX0sImRhdGVPZkJpcnRoIjoiMTk5OS8xMC8yMSIsImlzc3VlciI6ImRpZDp3ZWI6bW9zaXAuZ2l0aHViLmlvOmluamktY29uZmlnOnFhLWluamkxOm1vY2siLCJWSUQiOjEyMzQ1NiwicHJvdmluY2UiOlt7Imxhbmd1YWdlIjoiZnJhIiwidmFsdWUiOiJ5dcSBbiAyIn0seyJsYW5ndWFnZSI6ImFyYSIsInZhbHVlIjoi2YrZjtmP2KfZhuqJm-KljSJ9LHsibGFuZ3VhZ2UiOiJlbmciLCJ2YWx1ZSI6Inl1YW4gd2VlIn1dLCJpc3N1YW5jZURhdGUiOiIyMDI1LTA5LTA4VDEzOjQ0OjQ0LjU5NVoiLCJwaG9uZSI6Iis5MTk0MjczNTc5MzQiLCJjbmYiOnsia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKMWMyVWlPaUp6YVdjaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJa1pqWlRoR0xURlpjelpFUWpOTVNIQTJRVzlxVW13M2NVeDJVMVJmUlZWdGFGQm5jRk41V1VSeFdqQWlmUT09In0sImlkIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKMWMyVWlPaUp6YVdjaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJa1pqWlRoR0xURlpjelpFUWpOTVNIQTJRVzlxVW13M2NVeDJVMVJmUlZWdGFGQm5jRk41V1VSeFdqQWlmUT09IiwiVUlOIjoiMTIzNDU2IiwicmVnaW9uIjpbeyJsYW5ndWFnZSI6ImZyYSIsInZhbHVlIjoieXXEgW4gMyJ9LHsibGFuZ3VhZ2UiOiJhcmEiLCJ2YWx1ZSI6IiTZhNmP2Ybar--Al-GGkSJ9LHsibGFuZ3VhZ2UiOiJlbmciLCJ2YWx1ZSI6Inl1YW4gd2VlIDMifV0sImVtYWlsIjoic2l3ZXIua21AZ21haWwuY29tIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDI3LTA5LTA4VDEzOjQ0OjQ0LjU5NVoifQ.M-mFZVfWmyBCz-ML6yglTPMJhvVhlWZ2xqWlt7S1NJaqoXHPzTrZK6Sa1d-l223NKSivB6dTSwGumaeXhk4YCA~WyIyQW4wb25RVTJxWlVIOUwxa0VBWjBRIiwiZnVsbE5hbWUiLFt7Imxhbmd1YWdlIjoiZnJhIiwidmFsdWUiOiJBbGhlcmkgQm9iYnkifSx7Imxhbmd1YWdlIjoiYXJhIiwidmFsdWUiOiLYqtiq2q_ZhNiv2YPZhtiz2Y7YstmC2YfZkNmC2ZDZgdmEINiv2LPZitmK2LPZitmD2K_Zg9mG2YjapNmIIn0seyJsYW5ndWFnZSI6ImVuZyIsInZhbHVlIjoiQWxoZXJpIEJvYmJ5In1dXQ~"

    private val credentials = listOf(sdJwt2, sdJwt2)


    @BeforeTest
    fun setup() {

    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `test end-to-end build with real SD-JWT credentials`() {
        val builder = UnsignedSdJwtVPTokenBuilder(authorizationRequest = testAuthorizationRequest, specVersion = SpecVersion.DRAFT_23
        )

        val credential1 =
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, sdJwt2, "input-descriptor-id1")
        val credential2 =
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, sdJwt2, "input-descriptor-id2")
        val (payload, unsignedVPTokens) = builder.build(listOf(credential1, credential2))

        @Suppress("UNCHECKED_CAST")
        val uuidToUnsignedKBJWT = payload as? Map<String, String>
        assertNotNull(uuidToUnsignedKBJWT)
        assertEquals(credentials.size, unsignedVPTokens.size)

        uuidToUnsignedKBJWT.values.forEach { token ->
            val parts = token.split(".")
            assertEquals(2, parts.size)

            val decodedHeader = String(Base64.getUrlDecoder().decode(parts[0]))
            val decodedPayload = String(Base64.getUrlDecoder().decode(parts[1]))

            assertTrue(
                decodedHeader.contains("\"alg\":\"EdDSA\""),
                "Header missing alg=EdDSA: $decodedHeader"
            )
            assertTrue(
                decodedPayload.contains(nonce),
                "Nonce $nonce not in payload: $decodedPayload"
            )
        }

        // Check that identifiers in CredentialInputDescriptorMapping are updated to match the UUIDs in the unsigned vp token
        assertNotNull(credential1.identifier)
        assertNotNull(credential2.identifier)
        assertTrue(uuidToUnsignedKBJWT.keys.containsAll(listOf(credential1.identifier, credential2.identifier)))
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with multiple SD-JWT credentials`() {
        val mappings = credentials.mapIndexed { idx, cred ->
            CredentialInputDescriptorMapping(
                FormatType.DC_SD_JWT,
                cred,
                "input-descriptor-id${idx + 1}"
            )
        }
        val builder = UnsignedSdJwtVPTokenBuilder(authorizationRequest = testAuthorizationRequest, specVersion = SpecVersion.DRAFT_23
        )
        val (vpPayload, unsignedTokens) = builder.build(mappings)

        @Suppress("UNCHECKED_CAST")
        val uuidMap = vpPayload as? Map<String, String>
        assertNotNull(uuidMap)
        assertEquals(mappings.size, unsignedTokens.size)

        uuidMap.values.forEach { token ->
            val parts = token.split(".")
            assertEquals(2, parts.size)
            val decodedHeader = String(Base64.getUrlDecoder().decode(parts[0]))
            val decodedPayload = String(Base64.getUrlDecoder().decode(parts[1]))
            assertTrue(decodedHeader.contains("\"alg\":\"EdDSA\""))
            assertTrue(decodedPayload.contains(nonce))
        }
        uuidMap.keys.forEach { uuid ->
            val found = mappings.any { it.identifier == uuid }
            assertTrue(found, "UUID $uuid from unsigned token not found in mappings")
        }
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) update identifier in CredentialInputDescriptorMapping`() {
        val mapping = CredentialInputDescriptorMapping(
            FormatType.DC_SD_JWT,
            credentials[0],
            "input-descriptor-id1"
        )
        val builder = UnsignedSdJwtVPTokenBuilder(authorizationRequest = testAuthorizationRequest, specVersion = SpecVersion.DRAFT_23
        )
        val (_, _) = builder.build(listOf(mapping))

        assertNotNull(mapping.identifier)
    }
}