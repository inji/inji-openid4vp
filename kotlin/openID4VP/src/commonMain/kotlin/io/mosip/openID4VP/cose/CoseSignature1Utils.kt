package io.mosip.openID4VP.cose

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.mapSigningAlgorithmToProtectedAlg

internal object CoseSignature1Utils {
    fun createSignature1Structure(
        payload: ByteArray,
        alg: String,
        coseAlg: Long? = null
    ): ByteArray {
        val protectedHeaderMap = cborMapOf(
            1 to (coseAlg ?: mapSigningAlgorithmToProtectedAlg(alg))
        )
        val protectedHeaderBytes = encodeCbor(protectedHeaderMap)
        val protectedHeaderBstr = ByteString(protectedHeaderBytes)

        val sigStructure = cborArrayOf(
            "Signature1", // context
            protectedHeaderBstr, // body_protected
            ByteString(ByteArray(0)), // empty external_aad
            ByteString(payload)
        )

        return encodeCbor(sigStructure)
    }

    /**
     * Creates a COSE_Sign1 structure (the final signed message).
     *
     * COSE_Sign1 as defined in RFC 8152
     * COSE_Sign1 = [
     *   protected : bstr,
     *   unprotected : {},
     *   payload : nil,
     *   signature : bstr
     * ]
     *
     * @param signingAlgorithm The signing algorithm (e.g., "ES256")
     * @param signature The raw signature bytes
     * @return The COSE_Sign1 DataItem structure
     */
    fun createCoseSign1(
        signingAlgorithm: String,
        signature: ByteArray
    ): DataItem {
        val protectedSigningAlgorithm = mapSigningAlgorithmToProtectedAlg(signingAlgorithm)
        val protectedHeaderBytes = encodeCbor(cborMapOf(1 to protectedSigningAlgorithm))
        val protectedHeader = ByteString(protectedHeaderBytes)
        val unprotectedHeader = cborMapOf()
        val signatureBstr = ByteString(signature)

        return cborArrayOf(protectedHeader, unprotectedHeader, null, signatureBstr)
    }
}