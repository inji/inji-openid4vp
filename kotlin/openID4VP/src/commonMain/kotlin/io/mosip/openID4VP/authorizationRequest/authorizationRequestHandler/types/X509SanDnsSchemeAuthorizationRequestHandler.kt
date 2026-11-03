package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateRequestObjectSigningAlgSupported
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

private val className = X509SanDnsSchemeAuthorizationRequestHandler::class.simpleName!!

class X509SanDnsSchemeAuthorizationRequestHandler(
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
    // DNS name part of client_id: "x509_san_dns:example.com" -> "example.com"
    private val dnsName: String = clientId.removePrefix("${ClientIdPrefix.X509_SAN_DNS.value}:")

    // Leaf cert parsed from x5c in extractPublicKey; used later in validateClientAuthenticity
    private var leafCert: X509Certificate? = null

    override fun isSignedRequestSupported(): Boolean = true

    override fun isUnsignedRequestSupported(): Boolean = false

    override fun clientIdPrefix(): String = ClientIdPrefix.X509_SAN_DNS.value

    override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> {
        validateRequestObjectSigningAlgSupported(walletConfig)
        return walletConfig.toWalletMetadata(specVersion)
    }

    // Step 3: extract x5c from JWS header, parse leaf cert, return its public key.
    // Step 4 (signature verification with ES256) is handled by the base class calling
    // JWSHandler.verify() — TODO PR#232: ES256SignatureVerifierImpl must be wired there first.
    override fun extractPublicKey(algorithm: SignatureAlgorithm, jwsHeader: Map<String, Any>): PublicKey {
        @Suppress("UNCHECKED_CAST")
        val x5cList = jwsHeader["x5c"] as? List<String>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Missing x5c in JWS header for x509_san_dns client_id_scheme",
                className,
                "MISSING_X5C"
            )

        if (x5cList.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "x5c in JWS header is empty",
                className,
                "MISSING_X5C"
            )
        }

        val cf = CertificateFactory.getInstance("X.509")
        val certs = x5cList.map { entry ->
            val der = Base64.getDecoder().decode(entry)
            cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }

        leafCert = certs.first()
        return leafCert!!.publicKey
    }

    // Steps 5–7: cert validity, SAN match, response_uri host check.
    // Step 8 (RFC 5280 chain validation) is deferred — trust chain discussion pending.
    // TODO PR#232: validateCertificationPath(x5cChain, parsedTrustAnchors) once discussion settles.
    override fun validateClientAuthenticity() {
        val cert = leafCert
            ?: throw OpenID4VPExceptions.InvalidData(
                "x5c leaf certificate was not extracted — extractPublicKey must run first",
                className,
                "MISSING_X5C"
            )

        // Step 5: certificate validity period
        val now = Date()
        if (now.before(cert.notBefore)) {
            throw OpenID4VPExceptions.InvalidData(
                "Verifier certificate is not yet valid (notBefore: ${cert.notBefore})",
                className,
                "CERT_NOT_YET_VALID"
            )
        }
        if (now.after(cert.notAfter)) {
            throw OpenID4VPExceptions.InvalidData(
                "Verifier certificate has expired (notAfter: ${cert.notAfter})",
                className,
                "CERT_EXPIRED"
            )
        }

        // response_uri is always required regardless of skip flag
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
            ?: throw OpenID4VPExceptions.MissingInput(
                RESPONSE_URI.value, "", className, notifyVerifier = false
            )

        if (!walletConfig.skipSanDnsMatch) {
            // Step 6: SAN dNSName must match the DNS name from client_id
            val sanDnsNames = extractSanDnsNames(cert)
            if (sanDnsNames.none { matchesDnsName(it, dnsName) }) {
                throw OpenID4VPExceptions.InvalidData(
                    "No SAN dNSName entry matches client_id DNS name '$dnsName'. SANs: $sanDnsNames",
                    className,
                    "SAN_MISMATCH"
                )
            }

            // Step 7: response_uri must use HTTPS and its host must match the DNS name
            val parsedUri = try {
                URI(responseUri)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.InvalidData(
                    "response_uri is not a valid URI: $responseUri",
                    className,
                    "RESPONSE_URI_HOST_MISMATCH"
                )
            }

            if (parsedUri.scheme?.lowercase() != "https") {
                throw OpenID4VPExceptions.InvalidData(
                    "response_uri must use HTTPS for x509_san_dns client_id_scheme",
                    className,
                    "NOT_HTTPS"
                )
            }

            if (parsedUri.host != dnsName) {
                throw OpenID4VPExceptions.InvalidData(
                    "response_uri host '${parsedUri.host}' does not match client_id DNS name '$dnsName'",
                    className,
                    "RESPONSE_URI_HOST_MISMATCH"
                )
            }
        }
    }

    private fun extractSanDnsNames(cert: X509Certificate): List<String> {
        return cert.subjectAlternativeNames
            ?.filter { (it[0] as? Int) == 2 }  // 2 = dNSName per RFC 5280
            ?.mapNotNull { it[1] as? String }
            ?: emptyList()
    }

    // Matches exact name or single-level wildcard (*.example.com matches sub.example.com only)
    private fun matchesDnsName(sanEntry: String, name: String): Boolean {
        if (!sanEntry.startsWith("*.")) return sanEntry.equals(name, ignoreCase = true)
        val suffix = sanEntry.substring(1) // ".example.com"
        return name.endsWith(suffix, ignoreCase = true) &&
               name.indexOf('.') == name.length - suffix.length
    }
}