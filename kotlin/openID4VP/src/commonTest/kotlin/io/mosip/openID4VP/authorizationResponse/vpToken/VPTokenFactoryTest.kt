package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType
import kotlin.test.Test
import kotlin.test.assertTrue

class VPTokenFactoryTest {

    @Test
    fun `getVPTokenBuilder should return LdpVPTokenBuilder for LDP_VC`() {
        val builder = VPTokenFactory.getVPTokenBuilder(FormatType.LDP_VC)
        assertTrue(builder is LdpVPTokenBuilder)
    }

    @Test
    fun `getVPTokenBuilder should return MdocVPTokenBuilder for MSO_MDOC`() {
        val builder = VPTokenFactory.getVPTokenBuilder(FormatType.MSO_MDOC)
        assertTrue(builder is MdocVPTokenBuilder)
    }

    @Test
    fun `getVPTokenBuilder should return SdJwtVPTokenBuilder for SD_JWT formats`() {
        val dcBuilder = VPTokenFactory.getVPTokenBuilder(FormatType.DC_SD_JWT)
        val vcBuilder = VPTokenFactory.getVPTokenBuilder(FormatType.VC_SD_JWT)

        assertTrue(dcBuilder is SdJwtVPTokenBuilder)
        assertTrue(vcBuilder is SdJwtVPTokenBuilder)
    }
}

