package io.mosip.openID4VP


import io.mosip.openID4VP.authorizationRequest.*
import io.mosip.openID4VP.authorizationResponse.*
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenV2
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.*
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.common.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.verifier.VerifierResponse

class OpenID4VP @JvmOverloads constructor(
    private val traceabilityId: String,
    private var walletMetadata: WalletMetadata? = null
) {
    private var authorizationResponseHandler = AuthorizationResponseHandler(walletMetadata = walletMetadata)
    private var responseUri: String? = null
    private var walletNonce: String = generateNonce()
    var authorizationRequest: AuthorizationRequest? = null
    private val className = OpenID4VP::class.simpleName.orEmpty()


    /** Begins the authentication by validating the incoming Authorization request */
    @JvmOverloads
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = true
    ): AuthorizationRequest {
        return try {
            walletNonce = generateNonce()
            authorizationRequest = null
            responseUri = null
            authorizationResponseHandler = AuthorizationResponseHandler(walletMetadata)
            val authorizationRequest =
                AuthorizationRequest.validateAndCreateAuthorizationRequest(
                    urlEncodedAuthorizationRequest,
                    trustedVerifiers,
                    walletMetadata,
                    ::setResponseUri,
                    shouldValidateClient,
                    walletNonce
                )
            this.authorizationRequest = authorizationRequest
            authorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    @JvmOverloads
    fun authenticateVerifier(
        authorizationRequest: Map<String, Any>,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = true,
    ): AuthorizationRequest {
        return try {
            walletNonce = generateNonce()
            this.authorizationRequest = null
            responseUri = null
            authorizationResponseHandler = AuthorizationResponseHandler(walletMetadata)
            val validatedAuthorizationRequest =
                AuthorizationRequest.validateAndCreateAuthorizationRequest(
                    authorizationRequest,
                    trustedVerifiers,
                    walletMetadata,
                    ::setResponseUri,
                    shouldValidateClient,
                    walletNonce
                )
            this.authorizationRequest = validatedAuthorizationRequest
            validatedAuthorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    /** Builds the unsigned VP token from VCs */
    fun constructUnsignedVPToken(
        verifiableCredentials: Map<String, Map<FormatType, List<Any>>>,
        holderId: String? = null,
        signatureSuite: String? = null
    ): List<UnsignedVPTokenV2> {
        return try {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = verifiableCredentials,
                authorizationRequest = authorizationRequest!!,
                responseUri = responseUri!!,
                holderId = holderId,
                signatureSuite = signatureSuite,
                nonce = walletNonce
            )
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    fun constructVPResponse(vpTokenSigningResults: List<VPTokenSigningResultV2>): Map<String, Any> {
        return try {
            authorizationResponseHandler.constructVPResponse(
                authorizationRequest = authorizationRequest!!,
                vpTokenSigningResults = vpTokenSigningResults,
            )
        } catch (exception: OpenID4VPExceptions) {
            return constructErrorInfo(exception)
        }
    }


    /** Sends the final Authorization response to Verifier with the Verifiable Presentations as per response type
     * Returns the Verifier response as Verifier Response object
     * */
    fun sendVPResponseToVerifier(
        vpTokenSigningResults: List<VPTokenSigningResultV2>
    ): VerifierResponse {
        return try {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = authorizationRequest!!,
                vpTokenSigningResults = vpTokenSigningResults,
                responseUri = responseUri!!
            )
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    fun constructErrorInfo(exception: Exception): Map<String, Any> {
        return authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest!!,
            exception,
            walletNonce
        )
    }

    /**
     * Sends Authorization error to the Verifier and returns the response from the Verifier.
     * The response body from Verifier response is returned as a Verifier Response object.
     */
    fun sendErrorInfoToVerifier(exception: Exception): VerifierResponse {
        return authorizationResponseHandler.sendAuthorizationError(
            responseUri,
            authorizationRequest,
            exception
        )
    }

    private fun setResponseUri(uri: String) {
        this.responseUri = uri
    }

    // Ensures that any error occurring in the flow is sent to the Verifier
    // The Verifier's response is attached to the exception for further usage
    private fun safeSendError(exception: Exception) {
        try {
            val verifierResponse = sendErrorInfoToVerifier(exception)
            (exception as? OpenID4VPExceptions)?.setVerifierResponse(verifierResponse)
        } catch (error: Exception) {
            OpenID4VPExceptions.error(error.message ?: error.localizedMessage, className)
        }
    }
}
