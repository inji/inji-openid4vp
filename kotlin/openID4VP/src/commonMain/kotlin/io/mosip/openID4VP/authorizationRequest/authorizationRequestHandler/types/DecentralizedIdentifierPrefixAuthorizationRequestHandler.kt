package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.extractClientIdPartOnly
import io.mosip.openID4VP.authorizationRequest.validateRequestObjectSigningAlgSupported
import io.mosip.openID4VP.common.JacksonObjectMapper
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.net.URLDecoder
import java.security.PublicKey

private val className = DecentralizedIdentifierPrefixAuthorizationRequestHandler::class.simpleName!!

class DecentralizedIdentifierPrefixAuthorizationRequestHandler(
    clientId: String,
    specVersion: SpecVersion,
    authorizationRequestParameters: MutableMap<String, Any>,
    walletConfig: WalletConfig,
    setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit,
    walletNonce: String,
) : ClientIdPrefixBasedAuthorizationRequestHandler(
    clientId,
    specVersion,
    authorizationRequestParameters,
    walletConfig,
    setResponseDispatchInfo,
    walletNonce
) {
    override fun isSignedRequestSupported(): Boolean {
        return true
    }

    override fun isUnsignedRequestSupported(): Boolean {
        return false
    }

    override fun clientIdPrefix(): String {
        return ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value
    }

    override fun confirmSpecVersionIdentifiedFromRequest(): Boolean {
        return if (specVersion == SpecVersion.DRAFT_23) {
            clientId.startsWith(ClientIdScheme.DID.value)
        } else {
            clientId.startsWith(ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value)
        }
    }

    override fun validateClientAuthenticity() {
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value) ?: return

        val didUrl = when (specVersion) {
            SpecVersion.DRAFT_23 -> clientId
            SpecVersion.V1 -> extractClientIdPartOnly(authorizationRequestParameters)
        }

        // did:key and did:jwk are self-contained and have no service endpoints — skip
        if (!didUrl.startsWith("did:web:")) return

        val didDocumentUrl = constructDidWebDocumentUrl(didUrl)

        try {
            val response = sendHTTPRequest(didDocumentUrl, HttpMethod.GET)
            if (!response.isOk()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Failed to resolve DID document for response_uri validation: HTTP ${response.statusCode}",
                    className
                )
            }

            @Suppress("UNCHECKED_CAST")
            val didDocument = JacksonObjectMapper.instance.readValue(response.body, Map::class.java) as Map<String, Any>

            @Suppress("UNCHECKED_CAST")
            val services = didDocument["service"] as? List<Map<String, Any>> ?: emptyList()
            val serviceEndpoints = services.mapNotNull { it["serviceEndpoint"] as? String }

            if (responseUri !in serviceEndpoints) {
                throw OpenID4VPExceptions.InvalidData(
                    "response_uri '$responseUri' is not a service endpoint of client_id DID '$didUrl'",
                    className,
                    notifyVerifier = false
                )
            }
        } catch (e: OpenID4VPExceptions) {
            throw e
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Failed to validate response_uri against DID document: ${e.message}",
                className
            )
        }
    }

    private fun constructDidWebDocumentUrl(didUrl: String): String {
        val methodSpecificId = didUrl.removePrefix("did:web:")
        val idComponents = methodSpecificId.split(":")
        val baseDomain = URLDecoder.decode(idComponents.first(), "UTF-8")
        val path = idComponents.drop(1).joinToString("/")
        return if (path.isEmpty()) {
            "https://$baseDomain/.well-known/did.json"
        } else {
            "https://$baseDomain/$path/did.json"
        }
    }

    override fun extractPublicKey(algorithm: SignatureAlgorithm, kid: String?): PublicKey {
        val didUrl = when (specVersion) {
            SpecVersion.DRAFT_23 -> clientId
            SpecVersion.V1 -> extractClientIdPartOnly(authorizationRequestParameters)
        }
        if (kid.isNullOrEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "keyId is required to extract public key in decentralized_identifier client_id_prefix",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }
        return DidPublicKeyResolver().resolve(didUrl, kid)
    }

    override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> {
        validateRequestObjectSigningAlgSupported(walletConfig)
        return walletConfig.toWalletMetadata(specVersion)
    }
}
