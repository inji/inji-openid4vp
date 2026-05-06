package io.mosip.sampleapp.utils

import android.util.Log
import androidx.compose.runtime.snapshots.SnapshotStateList
import com.nimbusds.jose.jwk.OctetKeyPair
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.sampleapp.data.HardcodedOVPData.getListOfVerifiers
import io.mosip.sampleapp.data.HardcodedOVPData.getWalletMetadata
import io.mosip.sampleapp.data.VCMetadata
import io.mosip.sampleapp.utils.SampleKeyGenerator.SIGNATURE_SUITE
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyPair

object OpenID4VPManager {
    private var _instance: OpenID4VP? = null
    val instance: OpenID4VP
        get() = _instance ?: throw IllegalStateException("OpenID4VP is not initialized")

    fun init(traceabilityId: String) {
        _instance = OpenID4VP(traceabilityId, getWalletMetadata())
    }

    fun authenticateVerifier(
        urlEncodedAuthRequest: String
    ): AuthorizationRequest {
        return try {
            instance.authenticateVerifier(
                urlEncodedAuthorizationRequest = urlEncodedAuthRequest,
                trustedVerifiers = getListOfVerifiers(),
                shouldValidateClient = false
            )
        } catch (exception: Exception) {
            Log.e("OpenID4VP-sample wallet", "Error authenticating verifier ${exception.message}")
            throw exception
        }
    }

    private fun constructUnsignedVpToken(selectedCredentials: Map<String, Map<FormatType, List<Any>>>, holderId: String, signatureSuite: String): List<UnsignedVPToken> {
        return try {
            instance.constructUnsignedVPToken(selectedCredentials, holderId, signatureSuite)
        } catch (exception: Exception) {
            Log.e("OpenID4VP-sample wallet", "Error constructing Unsigned vp token: ${exception.message}")
            throw exception
        }
    }

    fun shareVerifiablePresentation(
        selectedItems: SnapshotStateList<Pair<String, VCMetadata>>,
        onResult: (VerifierResponse) -> Unit
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val result = sendVP(selectedItems)
                println("VP sharing result: $result")
                onResult(result)
            } catch (exception: Exception) {
                Log.e("OpenID4VP-sample wallet", "Error sharing Verifiable Presentation: ${exception.message}")
                throw exception
            }
        }
    }


    private suspend fun sendVP(selectedItems: SnapshotStateList<Pair<String, VCMetadata>>): VerifierResponse =
        withContext(
            Dispatchers.IO
        ) {
            val parsedSelectedItems = MatchingVcsHelper().buildSelectedVCsMapPlain(selectedItems)

            val ldpKeyType = KeyType.Ed25519
            val ldpKeyPair = SampleKeyGenerator.generateKeyPair(ldpKeyType)
            val holderId = DetachedJwtKeyManager.generateHolderId(ldpKeyPair as OctetKeyPair)

            val mdocKeyType = KeyType.ES256
            val mdocKeyPair = SampleKeyGenerator.generateKeyPair(mdocKeyType)

            val unsignedVPTokens = constructUnsignedVpToken(
                parsedSelectedItems,
                holderId, SIGNATURE_SUITE
            )

            val vpTokenSigningResults = unsignedVPTokens.map { unsignedToken ->
                when (unsignedToken.format) {
                    FormatType.LDP_VC -> {
                        val result = VPTokenSigner.signVpToken(
                            ldpKeyType,
                            unsignedToken.dataToSign,
                            ldpKeyPair
                        )
                        VPTokenSigningResult(
                            signedData = result.jws
                        )
                    }
                    FormatType.MSO_MDOC -> {
                        val bytes = unsignedToken.dataToSign.chunked(2)
                            .map { it.toInt(16).toByte() }
                            .toByteArray()
                        val signed = VPTokenSigner.signDeviceAuthentication(
                            mdocKeyPair as KeyPair,
                            mdocKeyType,
                            bytes
                        )
                        val jwsParts = signed.jws.split(".")
                        val signaturePart = if (jwsParts.size == 3) jwsParts[2] else signed.jws
                        VPTokenSigningResult(
                            signedData = signaturePart
                        )
                    }
                    else -> throw IllegalArgumentException("Unsupported format: ${unsignedToken.format}")
                }
            }

            try {
                val finalResponse = instance.sendVPResponseToVerifier(vpTokenSigningResults)
                Log.d("VP_SHARE", "######## $finalResponse")
                finalResponse
            } catch (e: Exception) {
                Log.e("VP_SHARE", "Error sharing VP", e)
                throw e
            }
        }

    fun sendErrorToVerifier(ovpException: OpenID4VPExceptions): VerifierResponse {
        return instance.sendErrorInfoToVerifier(ovpException)
    }
}
