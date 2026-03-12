package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2018
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.JsonWebSignature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.RSASignature2018
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = LdpVPTokenSigningResult::class.simpleName!!

data class LdpVPTokenSigningResult(
    val jws: String? = null,
    val proofValue: String? = null,
    val signatureAlgorithm: String
) : VPTokenSigningResult {
    fun validate() {
//        when (signatureAlgorithm) {
//            Ed25519Signature2020.value -> {
//                require(proofValue != "null" && validateField(proofValue, "String")) {
//                    throw OpenID4VPExceptions.InvalidInput(
//                        fieldPath = listOf("LdpVPTokenSigningResult", "proofValue"),
//                        className = className,
//                        fieldType = "String"
//                    )
//                }
//            }
//
//            JsonWebSignature2020.value, RSASignature2018.value, Ed25519Signature2018.value -> {
//                require(jws != "null" && validateField(jws, "String")) {
//                    throw OpenID4VPExceptions.InvalidInput(
//                        fieldPath = listOf("LdpVPTokenSigningResult", "jws"),
//                        className = className,
//                        fieldType = "String"
//                    )
//                }
//            }
//        }
    }
}