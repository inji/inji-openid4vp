# Migration Guide: inji-openid4vp 0.7.0 → 1.0.0

This guide helps Kotlin developers upgrade from **`inji-openid4vp` 0.7.0** to **1.0.0**.

Scope: **breaking changes in the Kotlin entry point(s)** - OpenID4VP class and its public API. 

Note: 
- The core flow and concepts remain the same, but method signatures and some data models have changed for better clarity and usability.
---

## Quick method communication overview

1. `OpenID4VP(traceabilityId = ..., walletConfig = ...)` initializes wallet capabilities and trusted verifier defaults.
2. `authenticateVerifier(...)` validates the incoming authorization request and stores request context for the session.
3. `constructUnsignedVPToken(selectedCredentials = ...)` builds signing work units (`Array<UnsignedVPToken>`) from user-approved credentials.
4. Your wallet signs each `UnsignedVPToken.dataToSign` using `holderKeyReference` and `signatureAlgorithm`, producing `Array<VPTokenSigningResult>`.
5. `constructVPResponse(...)` or `sendVPResponseToVerifier(...)` generates/sends the final VP response.

---

## Feature overview

1. 0.7.0
   1. Supported OpenID4VP draft 21 and draft 23, mainly Presentation Definition flows.
2. 1.0.0
   1. Supports OpenID4VP draft 23 (Presentation Definition) and 1.0 (DCQL).
   2. Removed draft 21 support.
   3. Improves integration by:
      - returning structured signing units (`UnsignedVPToken`) instead of opaque encoded blocks
      - centralizing capability and verifier settings in `WalletConfig`

---

## TL;DR (what you must change)

1. `OpenID4VP` construction changed:
   - **0.7.0**: `OpenID4VP(traceabilityId = ..., walletMetadata = ...)`
   - **1.0.0**: `OpenID4VP(traceabilityId = ..., walletConfig = ...)` (`walletConfig` has defaults)

2. `constructUnsignedVPToken(...)` changed significantly:
   - **0.7.0**: `constructUnsignedVPToken(verifiableCredentials = ..., holderId = ..., signatureSuite = ...)` accepted `Map<String, Map<FormatType, List<Any>>>` and returned `Map<FormatType, UnsignedVPToken>`
   - **1.0.0**: `constructUnsignedVPToken(selectedCredentials = ...)` accepts `Map<String, List<Credential>>` and returns `List<UnsignedVPToken>`; `holderId` / `signatureSuite` are no longer inputs

3. VP response construction/sending changed:
   - `constructVPResponse(vpTokenSigningResults = ...)` accepts `Map<FormatType, VPTokenSigningResult>`
   - `sendVPResponseToVerifier(vpTokenSigningResults = ...)` accepts `Map<FormatType, VPTokenSigningResult>`

4. For DCQL request processing, use `DCQLHelper.getMatchingCredentials(inputCredentials = ..., dcqlQuery = ...)` to match wallet's available credentials against incoming VP request before building `selectedCredentials`.

5. Deprecated and legacy V1/V2 0.7.0 entry-point methods are removed in 1.0.0, while the core methods remain with updated signatures.

---

## Before vs After: entry point construction

### 0.7.0 (old)

```kotlin
// Legacy 0.7.0 style (for migration reference)
val openID4VP = OpenID4VP(
    traceabilityId = "trace-id",
    walletMetadata: walletMetadata
)
```

### 1.0.0 (new)

```kotlin
import io.mosip.openID4VP.*

val walletConfig = WalletConfig(
    trustedVerifiers = trustedVerifiers,
    validateTrustedVerifier = true,
    // Optional: override defaults such as
    // vpFormatsSupported, clientIdPrefixesSupported,
    // requestObjectSigningAlgValuesSupported, etc.
)

val openID4VP = OpenID4VP(
    traceabilityId = "trace-id",
    walletConfig = walletConfig
)
```

Reference: `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/OpenID4VP.kt`

### Mapping `WalletMetadata` -> `WalletConfig`

If your 0.7.0 integration used the old Kotlin wallet metadata model below:

```kotlin
data class WalletMetadata(
    val presentationDefinitionURISupported: Boolean,
    val vpFormatsSupported: Map<VPFormatType, VPFormatSupported>,
    val clientIdSchemesSupported: Array<ClientIdScheme>,
    val requestObjectSigningAlgValuesSupported: Array<RequestSigningAlgorithm>?,
    val authorizationEncryptionAlgValuesSupported: Array<KeyManagementAlgorithm>?,
    val authorizationEncryptionEncValuesSupported: Array<ContentEncryptionAlgorithm>?,
    val responseTypesSupported: Array<ResponseType>
)
```

then migrate it to `WalletConfig` like this:

| Old `WalletMetadata` field                  | New `WalletConfig` parameter                | Migration note                                                |
|---------------------------------------------|---------------------------------------------|---------------------------------------------------------------|
| `vpFormatsSupported`                        | `vpFormatsSupported`                        | Same capability                                               |
| `clientIdSchemesSupported`                  | `clientIdPrefixesSupported`                 | `ClientIdScheme` values map to public `ClientIdPrefix` values |
| `requestObjectSigningAlgValuesSupported`    | `requestObjectSigningAlgValuesSupported`    | `RequestSigningAlgorithm` -> `SignatureAlgorithm`             |
| `authorizationEncryptionAlgValuesSupported` | `authorizationEncryptionAlgValuesSupported` | `KeyManagementAlgorithm` -> `EncryptionAlgorithm`             |
| `authorizationEncryptionEncValuesSupported` | `authorizationEncryptionEncValuesSupported` | `ContentEncryptionAlgorithm` -> `EncryptionMethod`            |
| `responseTypesSupported`                    | `responseTypesSupported`                    | Same capability - Response Types supported by the Wallet      |
| `presentationDefinitionURISupported`        | `isPresentationDefinitionUriSupported`      | Same capability  - Supports `presentation_definition_uri`     |

Additional fields now configured on `WalletConfig` in 1.0.0:

| `WalletConfig`-only field | Purpose                                                                                                                                                                                                | Migration note                                                                      |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `validateTrustedVerifier` | Boolean flag that determines whether client authentication for VP requests from clients with the **"Pre-registered"** client ID prefix should be validated against the wallet's trusted verifier list. | Previously provided as `shouldValidateClient` in the `authenticateVerifier` method. |
| `trustedVerifiers`        | The wallet's default list of pre-registered trusted verifiers.                                                                                                                                         | Previously provided as `trustedVerifiers` in the `authenticateVerifier` method.     |


Example migration:

```kotlin
val walletConfig = WalletConfig(
    isPresentationDefinitionUriSupported = true,
    vpFormatsSupported = mapOf(
        VPFormatType.LDP_VC to LdpVcFormatSupported(
            proofTypeValues = arrayOf("JsonWebSignature2020"),
            cryptoSuiteValues = emptyArray()
        ),
        VPFormatType.MSO_MDOC to MsoMdocVcFormatSupported(
            issuerAuthAlgValues = arrayOf(-7),
            deviceAuthAlgValues = arrayOf(-7)
        ),
        VPFormatType.DC_SD_JWT to SdJwtVcFormatSupported(
            sdJwtAlgValues = arrayOf("ES256"),
            kbJwtAlgValues = arrayOf("ES256")
        )
    ),
    clientIdPrefixesSupported = arrayOf(ClientIdPrefix.PRE_REGISTERED, ClientIdPrefix.REDIRECT_URI, ClientIdPrefix.DECENTRALIZED_IDENTIFIER),
    requestObjectSigningAlgValuesSupported = arrayOf(SignatureAlgorithm.ED_DSA),
    authorizationEncryptionAlgValuesSupported = arrayOf(EncryptionAlgorithm.ECDH_ES),
    authorizationEncryptionEncValuesSupported = arrayOf(EncryptionMethod.A256_GCM),
    responseTypesSupported = arrayOf(ResponseType.VP_TOKEN),
    trustedVerifiers = arrayOf(
        Verifier(
            clientId = "inji-mock-verify",
            responseUris = arrayOf("https://mock-verifier.inji.com/response"),
            jwksUri = "https://mock-verifier.inji.com/.well-known/jwks.json",
            allowUnsignedRequest = true
        )
    )
)
```

Notes:
- `ClientIdScheme.did` maps to `ClientIdPrefix.decentralizedIdentifier` in the current API.
- `validateTrustedVerifier` and `trustedVerifiers` are new `WalletConfig` concerns that were not part of this older `WalletMetadata` model.
- For the algorithm/encryption enums, direct `rawValue` conversion works when the old and new enum raw values match.

---

## Before vs After: `authenticateVerifier(...)`

### What stays conceptually the same
- You still validate verifier authorization requests and receive `AuthorizationRequest`.

### What changes in practice

1. **Trusted verifier configuration is now part of `WalletConfig`**

    * Configure trusted verifiers once via `walletConfig.trustedVerifiers`.
    * Do not pass trusted verifiers to `authenticateVerifier(...)`.

2. **Validation of pre-registered VP request clients is now configured through `WalletConfig`**

    * Configure the validation flag via `walletConfig.validateTrustedVerifier`.
    * Do not pass `shouldValidateClient` to `authenticateVerifier(...)`.

3. **Deprecated 0.7.0 overloads have been removed**

    * Overloads that accepted metadata or trust-related parameters at call time are no longer supported.


### 0.7.0 call signatures (old)

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
    trustedVerifiers = trustedVerifiers,
    shouldValidateClient = true
)
```

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    authorizationRequest = authorizationRequestMap,
    trustedVerifiers = trustedVerifiers,
    shouldValidateClient = true
)
```

### 1.0.0 call (URL-encoded)

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest = encodedAuthorizationRequest
)
```

### 1.0.0 call (dictionary input)

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    authorizationRequest = authorizationRequestMap
)
```

Reference: `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/OpenID4VP.kt`

---

## Before vs After: `constructUnsignedVPToken(...)` (biggest change)

### Old behavior (0.7.0)

In 0.7.0, the main public method was:

```kotlin
val unsignedVPTokensByFormat: Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(
    verifiableCredentials = verifiableCredentials,
    holderId = holderId,
    signatureSuite = signatureSuite
)
```

Where:
- `verifiableCredentials` type was `Map<String, Map<FormatType, Array<AnyCodable>>>`
- the return type was `Map<FormatType, UnsignedVPToken>`
- `holderId` and `signatureSuite` were optional inputs used by older LDP VP construction flows

0.7.0 also exposed `constructUnsignedVPTokenV2(...) -> Array<UnsignedVPTokenV2>`, which is removed in 1.0.0.

### New behavior (1.0.0)

In 1.0.0, `constructUnsignedVPToken(selectedCredentials = ...)` returns **typed list of signing work units**:

```kotlin
val unsignedVPTokens: Array<UnsignedVPToken> = openID4VP.constructUnsignedVPToken(
    selectedCredentials = selectedCredentials
)
```

`selectedCredentials` shape:
- type: `Map<String, Array<Credential>>`
- key: `input_descriptor.id` (Presentation Definition) or `credential_query.id` (DCQL)
- value: selected credentials where each `Credential` has:
  - `format: FormatType`
  - `data = AnyCodable`
  - `credentialId = String`

Example:

```kotlin
val selectedCredentials: Map<String, Array<Credential>> = mapOf(
    "age_descriptor" to arrayOf(
        Credential(
            format = FormatType.LDP_VC,
            data = AnyCodable(
                mapOf(
                    "@context" to arrayOf("https://www.w3.org/2018/credentials/v1"),
                    "type" to arrayOf("VerifiableCredential", "AgeCredential"),
                    "credentialSubject" to mapOf(
                        "id" to "did:example:holder-001",
                        "ageOver18" to true
                    )
                )
            ),
            credentialId = "cred-age-001"
        )
    ),
    "email_query" to arrayOf(
        Credential(
            format = FormatType.DC_SD_JWT,
            data = AnyCodable("<compact-dc-sd-jwt-vc>"),
            credentialId = "cred-email-777"
        )
    )
)
// Note: The credentials shown here are for illustrative purposes.
```

`holderId` and `signatureSuite` are removed from this API. 1.0.0 resolves signing requirements inside the SDK and returns them via `UnsignedVPToken`.

Each `UnsignedVPToken` provides:
- `format: FormatType`
- `holderKeyReference: String`
- `signatureAlgorithm: String`
- `dataToSign: ByteArray`

Wallet signing step:

```kotlin
val vpTokenSigningResults: Array<VPTokenSigningResult> = unsignedVPTokens.map { unsignedVPToken ->
    val signature: ByteArray = walletKeyManager.sign(
        data = unsignedVPToken.dataToSign,
        keyReference = unsignedVPToken.holderKeyReference,
        algorithm = unsignedVPToken.signatureAlgorithm
    )

    VPTokenSigningResult(id = unsignedVPToken.id, signedData = signature)
}
```

References:
- `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/OpenID4VP.kt`
- `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/unsignedVPToken/UnsignedVPToken.kt`
- `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/vpTokenSigningResult/VPTokenSigningResult.kt`

---

## Before vs After: `constructVPResponse(...)`

### 0.7.0 (old)

```kotlin
val response: Map<String, Any> = openID4VP.constructVPResponse(
    vpTokenSigningResults = oldSigningResultsByFormat
)
```

Signature:
- `constructVPResponse(vpTokenSigningResults = Map<FormatType, VPTokenSigningResult>) -> Map<String, Any>`

### 1.0.0 usage

```kotlin
val response: Map<String, Any> = openID4VP.constructVPResponse(
    vpTokenSigningResults = vpTokenSigningResults
)
```

Signature:
- `constructVPResponse(vpTokenSigningResults = Array<VPTokenSigningResult>) -> Map<String, Any>`

Behavior note:
- If VP response construction fails internally, it returns error info (`constructErrorInfo(exception = ...)`) instead of throwing.

---

## DCQL helper: `getMatchingCredentials(...)` from `DCQLHelper`

In 1.0.0, DCQL credential matching is available via `DCQLHelper`:

```kotlin
import io.mosip.openID4VP.*

val dcqlHelper = DCQLHelper(
    jsonLdExpander = null // Optional callback to pre-expand credential JSON-LD before evaluation
)

val matchingResult = dcqlHelper.getMatchingCredentials(
    inputCredentials = walletAvailableCredentials,
    dcqlQuery = dcqlQuery
)
```

Use this to evaluate all wallet credentials against incoming DCQL constraints before calling `constructUnsignedVPToken(selectedCredentials = ...)`.

You can down-cast the validated request to `AuthorizationDcqlRequest` and use its public `dcqlQuery` to run DCQL matching with `DCQLHelper`.

Reference: `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/helpers/DCQLHelper.kt`

---

## Before vs After: `sendVPResponseToVerifier(...)`

### 0.7.0 (old)

```kotlin
val verifierResponse: VerifierResponse = openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults = oldSigningResultsByFormat
)
```

Signature:
- `sendVPResponseToVerifier(vpTokenSigningResults = Map<FormatType, VPTokenSigningResult>): VerifierResponse`

### 1.0.0 usage

```kotlin
val verifierResponse: VerifierResponse = openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults = vpTokenSigningResults
)
```

Signature:
- `sendVPResponseToVerifier(vpTokenSigningResults = Array<VPTokenSigningResult>): VerifierResponse`

---

## Removed and changed entry-point methods from 0.7.0 (update your call sites)

> **Notice**
>
> 1.0.0 keeps the core entry point class, but several 0.7.0 methods were removed and some existing methods changed signatures.

Current public methods in `OpenID4VP` 1.0.0:
- `authenticateVerifier(urlEncodedAuthorizationRequest = ...)`
- `authenticateVerifier(authorizationRequest = ...)`
- `constructUnsignedVPToken(selectedCredentials = ...)`
- `constructVPResponse(vpTokenSigningResults = ...)`
- `constructErrorInfo(exception = ...)`
- `sendVPResponseToVerifier(vpTokenSigningResults = ...)`
- `sendErrorInfoToVerifier(exception = ...)`

For DCQL matching, use `DCQLHelper`:
- `getMatchingCredentials(inputCredentials = ..., dcqlQuery = ...)`

For detailed usage refer the [latest integration guide](../integration-guide.md)

### API Signature Changes

The following APIs have updated signatures in 1.0.0:

* `authenticateVerifier(urlEncodedAuthorizationRequest = ...)`

    * Trusted verifier and shouldValidateClient configuration is now sourced from `WalletConfig` and is no longer passed at call time.

* `authenticateVerifier(authorizationRequest = ...)`

    * Trusted verifier configuration is now sourced from `WalletConfig` and is no longer passed at call time.

* `constructUnsignedVPToken(selectedCredentials = ...)`

    * VP construction now operates on selected credentials directly, removing the need to provide holder identifiers and signature suites at call time.

* `constructVPResponse(vpTokenSigningResults = ...)`

    * The signing result collection no longer requires a `FormatType` mapping.

* `sendVPResponseToVerifier(vpTokenSigningResults = ...)`

    * The signing result collection no longer requires a `FormatType` mapping.

The following APIs are unchanged in 1.0.0:

* `constructErrorInfo(exception = ...)`
* `sendErrorInfoToVerifier(exception = ...)`


0.7.0 methods removed in 1.0.0:
- `constructUnsignedVPTokenV2(...)`
- `constructVPResponseV2(...)`
- `shareVerifiablePresentation(vpTokenSigningResults = ...)`
- `authenticateVerifier(urlEncodedAuthorizationRequest = ..., trustedVerifierJSON = ..., shouldValidateClient = ..., walletMetadata = ...)`
- `authenticateVerifier(urlEncodedAuthorizationRequest = ..., trustedVerifierJSON = ..., shouldValidateClient = ...)`
- `constructVerifiablePresentationToken(verifiableCredentials = ...)`
- `shareVerifiablePresentation(vpResponseMetadata = ...)`
- `sendErrorToVerifier(exception = ...)`

---

## Illustrative Kotlin Integration Skeleton

```kotlin
import io.mosip.openID4VP.*

fun handleOVPFlow(
    applicationId: String,
    encodedAuthorizationRequest: String,
    trustedVerifiers: Array<Verifier>,
    walletAvailableCredentials: Array<Credential>
) {
    val walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers)
    val openID4VP = OpenID4VP(traceabilityId = applicationId, walletConfig = walletConfig)

    val validatedVPRequest = openID4VP.authenticateVerifier(
        urlEncodedAuthorizationRequest = encodedAuthorizationRequest
    )

    val selectedCredentials: Map<String, Array<Credential>> =
        if (validatedVPRequest is AuthorizationDcqlRequest) {
            val dcqlHelper = DCQLHelper(jsonLdExpander = ::jsonLdExpanderCallback)
            val matchingVcsResult = dcqlHelper.getMatchingCredentials(
                inputCredentials = walletAvailableCredentials,
                dcqlQuery = validatedVPRequest.dcqlQuery
            )
            val result = getShareableCredentialsWithConsent(matchingVcsResult)
            if (result.second) {
                val verifierResponse = openID4VP.sendErrorInfoToVerifier(
                    exception = AccessDenied(
                        message = "User rejected to share credentials",
                        className = "SampleWalletApp"
                    )
                )
                handleVerifierResponse(verifierResponse)
                return
            }
            result.first
        } else if (validatedVPRequest is AuthorizationPresentationExchangeRequest) {
            val result = getCredentialsForVPRequestWithConsent(validatedVPRequest)
            if (result.second) {
                val verifierResponse = openID4VP.sendErrorInfoToVerifier(
                    exception = AccessDenied(
                        message = "User rejected to share credentials",
                        className = "SampleWalletApp"
                    )
                )
                handleVerifierResponse(verifierResponse)
                return
            }
            result.first
        } else {
            val verifierResponse = openID4VP.sendErrorInfoToVerifier(
                exception = InvalidData(
                    message = "Unexpected request type",
                    className = "SampleWalletApp"
                )
            )
            handleVerifierResponse(verifierResponse)
            return
        }

    val unsignedVpTokens = openID4VP.constructUnsignedVPToken(
        selectedCredentials = selectedCredentials
    )

    val signingResults = unsignedVpTokens.map { unsignedVPToken ->
        VPTokenSigningResult(
            id = unsignedVPToken.id,
            signedData = signData(
                dataToSign = unsignedVPToken.dataToSign,
                keyReference = unsignedVPToken.holderKeyReference,
                algorithm = unsignedVPToken.signatureAlgorithm
            )
        )
    }

    val vpSubmissionVerifierResponse = openID4VP.sendVPResponseToVerifier(
        vpTokenSigningResults = signingResults
    )
    handleVerifierResponse(vpSubmissionVerifierResponse)
}

fun jsonLdExpanderCallback(data: Map<String, Any>): Map<String, Any> = data

fun getShareableCredentialsWithConsent(
    matchingVcsResult: MatchingCredentialsResult
): Pair<Map<String, Array<Credential>>, Boolean> = Pair(emptyMap(), false)

fun getCredentialsForVPRequestWithConsent(
    vpRequest: AuthorizationPresentationExchangeRequest
): Pair<Map<String, Array<Credential>>, Boolean> = Pair(emptyMap(), false)

fun signData(dataToSign: ByteArray, keyReference: String, algorithm: String): ByteArray = byteArrayOf()

fun handleVerifierResponse(verifierResponse: VerifierResponse) {}
```

Notes:
- The crypto implementations like signing data is kept in your wallet app while the SDK focuses on VP request validation/VP response construction and sending to Verifier.

---

## Appendix: Key Kotlin Types and Entry Points

The following files contain the primary types and APIs used throughout the SDK:

* **Entry point**
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/OpenID4VP.kt`
* **Wallet configuration and credential models**
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationRequest/WalletMetadata.kt`
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/vpToken/Credential.kt`
* **DCQL utilities**
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/helpers/DCQLHelper.kt`
* **Signing work units**
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/unsignedVPToken/UnsignedVPToken.kt`
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/vpTokenSigningResult/VPTokenSigningResult.kt`
* **Callback type definitions**
    * `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/constants/FormatType.kt`
