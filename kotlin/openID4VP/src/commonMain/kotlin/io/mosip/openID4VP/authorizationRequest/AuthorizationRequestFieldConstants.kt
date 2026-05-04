package io.mosip.openID4VP.authorizationRequest

enum class AuthorizationRequestFieldConstants(val value: String) {
    CLIENT_ID ("client_id"),
    RESPONSE_TYPE ("response_type"),
    RESPONSE_MODE ("response_mode"),
    PRESENTATION_DEFINITION ("presentation_definition"),
    PRESENTATION_DEFINITION_URI ("presentation_definition_uri"),
    RESPONSE_URI ("response_uri"),
    REDIRECT_URI ("redirect_uri"),
    REQUEST_URI ("request_uri"),
    REQUEST ("request"),
    REQUEST_URI_METHOD ("request_uri_method"),
    NONCE ("nonce"),
    WALLET_NONCE ("wallet_nonce"),
    STATE ("state"),
    CLIENT_METADATA ("client_metadata"),
    TRANSACTION_DATA ("transaction_data"),
    DCQL_QUERY ("dcql_query"),
}
