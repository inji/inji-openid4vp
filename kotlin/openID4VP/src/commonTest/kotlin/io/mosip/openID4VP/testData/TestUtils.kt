package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.JWSUtil.Companion.createJWS
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import kotlinx.serialization.json.JsonObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import java.lang.reflect.Field
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import kotlin.test.assertEquals

fun toJavaPublicKey(multibase: String, keyType: String): PublicKey {
    try {
        val rawPublicKeyWithHeader = io.ipfs.multibase.Base58.decode(multibase.substring(1))
        val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
        val publicKey = Hex.decode(DER_PUBLIC_KEY_PREFIX) + rawPublicKey
        val pubKeySpec = X509EncodedKeySpec(publicKey)
        val keyFactory = KeyFactory.getInstance(keyType, BouncyCastleProvider())
        return keyFactory.generatePublic(pubKeySpec)
    } catch (e: Exception) {
        println("Error while getting public key object from Multibase: ${e.message}")
        throw PublicKeyNotFoundException("Public key object is null")
    }
}


fun setField(instance: Any, fieldName: String, value: Any?) {
    val field: Field = instance::class.java.getDeclaredField(fieldName)
    field.isAccessible = true
    field.set(instance, value)
}

fun createUrlEncodedData(
    requestParams: Map<String, String?>,
    verifierSentAuthRequestByReference: Boolean? = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: List<String>? = null,
    draftVersion: Int = 23,
): String {
    val paramList = when (verifierSentAuthRequestByReference) {
        true -> {
            if (draftVersion == 23)
                authRequestParamsByReferenceDraft23
            else
                authRequestParamsByReferenceDraft21
        }

        else -> applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    }
    val authorizationRequestParam =
        createAuthorizationRequest(paramList, requestParams, draftVersion) as Map<String, Any>

    val charset = StandardCharsets.UTF_8.toString()

    val queryString = authorizationRequestParam.entries.joinToString("&") {
        "${it.key}=${URLEncoder.encode(it.value?.toString() ?: "", charset)}"
    }
//    val urlEncodedQueryParameters = URLEncoder.encode(queryString, charset)
    return "openid4vp://authorize?$queryString"

}

fun createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: Map<String, String>,
    applicableFields: List<String>? = null,
    addValidSignature: Boolean? = true,
    jwtHeader: JsonObject? = null,
    isPresentationDefinitionUriPresent: Boolean? = false,
    draftVersion: Int = 23,
    removeClientId: Boolean = false,
): Any {
    val paramList =
        applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    return createAuthorizationRequest(
        paramList,
        authorizationRequestParams,
        draftVersion
    ).let { authRequestParam ->

        val param = if (isPresentationDefinitionUriPresent != true) {
            authRequestParam + clientMetadataPresentationDefinitionMap
        } else {
            if (clientIdScheme != ClientIdScheme.PRE_REGISTERED) {
                authRequestParam + mapOf(
                    CLIENT_METADATA.value to clientMetadataMap
                )
            } else {
                authRequestParam
            }
        }.toMutableMap()

        if (removeClientId) {
            param.remove(CLIENT_ID.value)
        }

        createJWS(param, addValidSignature!!, jwtHeader)

    }
}

internal fun createAuthorizationRequest(
    paramList: List<String>,
    requestParams: Map<String, String?>,
    draftVersion: Int = 23,
    isSigned: Boolean = false,
): MutableMap<String, String?> {
    var params: List<String> = paramList
    if (draftVersion == 21) {
        params = paramList + listOf(CLIENT_ID_SCHEME.value)
    }
    var authorizationRequestParam = params
        .filter { requestParams.containsKey(it) }
        .associateWith { requestParams[it] }
        .toMutableMap()
    if(isSigned) {
        val signedRequest = createJWS(authorizationRequestParam, true, null)
        authorizationRequestParam = mutableMapOf("request" to signedRequest, CLIENT_ID.value to requestParams[CLIENT_ID.value])
    }

    return authorizationRequestParam
}

fun assertOpenId4VPException(exception: OpenID4VPExceptions, expectedMessage: String, expectedErrorCode: String, expectedVerifierResponse: String? = null) {
    assertEquals(expectedMessage, exception.message)
    assertEquals(expectedErrorCode, exception.errorCode)
    if(expectedVerifierResponse != null){
        assertEquals(expectedVerifierResponse.toString(), exception.verifierResponse.toString())
    }
}

