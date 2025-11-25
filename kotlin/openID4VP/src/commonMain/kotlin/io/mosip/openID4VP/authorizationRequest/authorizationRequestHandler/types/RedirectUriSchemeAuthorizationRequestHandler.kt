package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REDIRECT_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.extractClientIdentifier
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.ResponseMode.DIRECT_POST
import io.mosip.openID4VP.constants.ResponseMode.DIRECT_POST_JWT
import io.mosip.openID4VP.constants.ResponseMode.IAR_POST
import io.mosip.openID4VP.constants.ResponseMode.IAR_POST_JWT
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.security.PublicKey
import java.util.logging.Logger

private val className = RedirectUriSchemeAuthorizationRequestHandler::class.simpleName!!

class RedirectUriSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    walletNonce: String
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters,walletMetadata, setResponseUri, walletNonce) {
    private val logger = Logger.getLogger(className)

    override fun isSignedRequestSupported(): Boolean {
        return false
    }

    override fun isUnsignedRequestSupported(): Boolean {
        return true
    }

    override fun clientIdScheme(): String {
        return ClientIdScheme.REDIRECT_URI.value
    }

    override fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey {
        throw UnsupportedOperationException("Public key extraction is not supported for redirect_uri client_id_scheme")
    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        val updatedWalletMetadata = walletMetadata
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = null
        return updatedWalletMetadata
    }

    override fun validateAndParseRequestFields(){
        super.validateAndParseRequestFields()
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?:
        throw OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value),"", className)
         when (responseMode) {
            DIRECT_POST.value, DIRECT_POST_JWT.value -> {
                validateUriCombinations(
                    authorizationRequestParameters,
                    RESPONSE_URI.value,
                    REDIRECT_URI.value
                )
            }
             IAR_POST.value, IAR_POST_JWT.value -> {
                 logger.info("IAR_POST or IAR_POST_JWT response_mode is used")
             }
            else -> throw OpenID4VPExceptions.InvalidData("Given response_mode is not supported", className)
        }
    }

    private fun validateUriCombinations(
        authRequestParam: Map<String, Any>,
        validAttribute: String,
        inValidAttribute: String,
    )  {
        when {
            authRequestParam.containsKey(inValidAttribute) -> {
                throw OpenID4VPExceptions.InvalidData("$inValidAttribute should not be present for given response_mode", className)
            }
            else -> {
                val data = getStringValue(authRequestParam, validAttribute)
                validate(validAttribute,data, className)
            }
        }
        if(authRequestParam[validAttribute] != extractClientIdentifier(authRequestParam))
            throw OpenID4VPExceptions.InvalidData("$validAttribute should be equal to client_id for given client_id_scheme", className)

    }

}