package io.mosip.openID4VP.constants

private const val PERCENT_ENCODED_PATTERN = "%[0-9a-fA-F]{2}"
private const val DID_ID_CHARACTER_PATTERN =
    "(?:[a-zA-Z0-9._-]|$PERCENT_ENCODED_PATTERN)"
private const val DID_FRAGMENT_CHARACTER_PATTERN =
    "(?:[a-zA-Z0-9._~!\\x24&'()*+,;=:@/?-]|$PERCENT_ENCODED_PATTERN)"

internal val SUPPORTED_HOLDER_DID_PATTERN = Regex(
    "^(?:did:jwk:[a-zA-Z0-9_-]+(?:#0)?|" +
            "did:key:(?:z[a-km-zA-HJ-NP-Z1-9]+|u[a-zA-Z0-9_-]+)" +
            "(?:#$DID_FRAGMENT_CHARACTER_PATTERN+)?|" +
            "did:web:(?:$DID_ID_CHARACTER_PATTERN*:)*$DID_ID_CHARACTER_PATTERN+" +
            "(?:#$DID_FRAGMENT_CHARACTER_PATTERN+)?)$"
)
