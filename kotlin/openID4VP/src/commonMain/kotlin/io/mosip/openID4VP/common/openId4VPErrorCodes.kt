package io.mosip.openID4VP.common

object OpenID4VPErrorCodes {
    const val INVALID_REQUEST = "invalid_request"
    const val INVALID_REQUEST_OBJECT = "invalid_request_object"
    const val ACCESS_DENIED = "access_denied"
    const val INVALID_CLIENT = "invalid_client"
    const val INVALID_SCOPE = "invalid_scope"
    const val INVALID_PRESENTATION_DEFINITION_URI = "invalid_presentation_definition_uri"
    const val VP_FORMATS_NOT_SUPPORTED = "vp_formats_not_supported"
    const val INVALID_PRESENTATION_DEFINITION_REFERENCE = "invalid_presentation_definition_reference"
    const val INVALID_REQUEST_URI_METHOD = "invalid_request_uri_method"
    const val INVALID_TRANSACTION_DATA = "invalid_transaction_data"
    const val SERVER_ERROR = "server_error"

    //  Custom Error Codes
    const val ERROR_DISPATCH_FAILURE = "error_dispatch_failure"
}

object OpenID4VPErrorFields {
    const val ERROR = "error"
    const val ERROR_DESCRIPTION = "error_description"
    const val STATE = "state"
}
