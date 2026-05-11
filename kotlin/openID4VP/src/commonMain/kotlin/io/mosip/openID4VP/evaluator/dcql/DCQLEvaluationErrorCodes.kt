package io.mosip.openID4VP.evaluator.dcql

enum class DCQLEvaluationErrorCodes(val value: String) {
    NO_MATCHING_FORMATS_FOUND("no_matching_credentials_with_requested_credential_formats_found"),
    CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH("cryptographic_holderbinding_or_meta_filter_mismatch"),
    NO_CLAIMS_SET_OPTION_SATISFIED("no_claims_set_option_satisfied"),
    CLAIM_UNAVAILABLE("claim_unavailable"),
    CLAIM_VALUE_MISMATCH("claim_value_not_matching"),
    REQUIRED_CLAIMS_NOT_SATISFIED("required_claims_not_satisfied");
}
