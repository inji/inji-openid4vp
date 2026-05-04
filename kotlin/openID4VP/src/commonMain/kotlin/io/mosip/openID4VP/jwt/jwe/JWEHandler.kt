package io.mosip.openID4VP.jwt.jwe

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.util.Base64URL
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider

private val className = JWEHandler::class.simpleName!!

class JWEHandler(
    private val keyEncryptionAlg: String,
    private val contentEncryptionAlg: String,
    private val publicKey: Jwk,
    private val walletNonce: String,
    private val verifierNonce: String
) {

    fun generateEncryptedResponse(payload: Map<String, Any>): String {
        try {
            val payloadString = io.mosip.openID4VP.common.getObjectMapper().writeValueAsString(payload)

            val header = JWEHeader.Builder(
                JWEAlgorithm.parse(keyEncryptionAlg),
                EncryptionMethod.parse(contentEncryptionAlg)
            )
                .keyID(publicKey.kid)
                .agreementPartyUInfo(Base64URL(walletNonce))
                .agreementPartyVInfo(Base64URL(verifierNonce))
                .build()

            val encrypter = EncryptionProvider.getEncrypter(publicKey)
            val jweObject = JWEObject(header, Payload(payloadString))
            jweObject.encrypt(encrypter)

            return jweObject.serialize()
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.JweEncryptionFailure(className, exception)
        }
    }
}