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
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.sampleapp.data.HardcodedOVPData.getWalletConfig
import io.mosip.sampleapp.data.VCMetadata
import io.mosip.openID4VP.wallet.Credential
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
        _instance = OpenID4VP(traceabilityId, getWalletConfig())
    }

    fun authenticateVerifier(
        urlEncodedAuthRequest: String
    ): AuthorizationRequest {
        return try {
            instance.authenticateVerifier(
                urlEncodedAuthorizationRequest = urlEncodedAuthRequest
            )
        } catch (exception: Exception) {
            Log.e("OpenID4VP-sample wallet", "Error authenticating verifier ${exception.message}")
            throw exception
        }
    }

    private fun constructUnsignedVpToken(selectedCredentials: Map<String, List<Credential>>): List<UnsignedVPToken> {
        return try {
            instance.constructUnsignedVPToken(selectedCredentials)
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

            val mdocKeyType = KeyType.ES256
            val mdocKeyPair = SampleKeyGenerator.generateKeyPair(mdocKeyType)

            val unsignedVPTokens = constructUnsignedVpToken(
                parsedSelectedItems
            )

            val vpTokenSigningResults = unsignedVPTokens.map { unsignedToken ->
                when (unsignedToken.format) {
                    FormatType.LDP_VC -> {
                        val result = VPTokenSigner.signVpToken(
                            ldpKeyType,
                            unsignedToken.dataToSign,
                            ldpKeyPair
                        )
                        val jwsParts = result.jws.split("..")
                        val signatureB64Url = if (jwsParts.size == 2) jwsParts[1] else result.jws
                        val signatureBytes = java.util.Base64.getUrlDecoder().decode(signatureB64Url)
                        VPTokenSigningResult(
                            id = unsignedToken.id,
                            signedData = signatureBytes
                        )
                    }
                    FormatType.MSO_MDOC -> {
                        val signed = VPTokenSigner.signDeviceAuthentication(
                            mdocKeyPair as KeyPair,
                            mdocKeyType,
                            unsignedToken.dataToSign
                        )
                        val jwsParts = signed.jws.split(".")
                        val signaturePart = if (jwsParts.size == 3) jwsParts[2] else signed.jws
                        val signatureBytes = java.util.Base64.getUrlDecoder().decode(signaturePart)
                        VPTokenSigningResult(
                            id = unsignedToken.id,
                            signedData = signatureBytes
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
