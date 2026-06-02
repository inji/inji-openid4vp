# Migration Guide: inji-openid4vp 0.7.0 -> 0.8.0

This guide helps developers upgrade from **`inji-openid4vp` 0.7.0** to **0.8.0**.

Scope: **breaking changes in the Kotlin entry point**
- `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/OpenID4VP.kt`

---

## Quick method communication overview

1. `OpenID4VP(traceabilityId, walletConfig)` initializes wallet capabilities and trusted verifier defaults.
2. `authenticateVerifier(...)` validates the incoming authorization request and stores request context for the session.
3. `constructUnsignedVPToken(selectedCredentials)` builds the data to be signed by the Wallet consumer app (`List<UnsignedVPToken>`) from user-approved credentials.
4. Your wallet signs each `UnsignedVPToken.dataToSign` using `holderKeyReference` and `signatureAlgorithm`, producing `List<VPTokenSigningResult>`.
5. `constructVPResponse(...)` or `sendVPResponseToVerifier(...)` uses those signing results to generate/send the final VP response.

---

## Feature overview

1. 0.7.0 
   1. supported OpenID4VP spec version draft 21 and draft 23 with a focus on Presentation Definition flows.
2. 0.8.0 
   1. supports OpenID4VP spec version draft 23 with Presentation Definition and Version 1.0 with DCQL flow
   2. Support for draft 21 is removed in 0.8.0 to focus on the latest spec version, which has been stable for a while and is widely adopted.
   3. Enhances the consumer experience by:
      - returning structured signing work units (`UnsignedVPToken`) instead of opaque encoded structures ensuring consumer focuses on only signing the data and not interpreting the structure for signing inputs.
      - centralizing wallet capabilities in `WalletConfig` instead of spreading them across method arguments, simplifying the entry point API and making it easier to manage wallet capabilities in one place.

---

## TL;DR (what you must change)

1. `OpenID4VP` construction changed:
   - **0.7.0**: `OpenID4VP(traceabilityId, walletMetadata)`
   - **0.8.0**: `OpenID4VP(traceabilityId, walletConfig)` (defaults available)

2. `constructUnsignedVPToken(...)` changed significantly:
   - **0.7.0**: constructed an encoded structure for signing (older `holderId` / `signatureSuite` flow)
   - **0.8.0**: returns `List<UnsignedVPToken>` with resolved signing inputs (`holderKeyReference`, `signatureAlgorithm`, `dataToSign`)

3. VP response construction/sending changed:
   - `constructVPResponse(...)` now takes `List<VPTokenSigningResult>`
   - `sendVPResponseToVerifier(...)` now takes `List<VPTokenSigningResult>`

4. For DCQL request processing, use `DCQLHelper.getMatchingCredentials(inputCredentials, dcqlQuery)` to match your wallet's available credentials against the incoming DCQL query before building `selectedCredentials`.

5. All deprecated 0.7.0 entry-point methods are removed in 0.8.0.

---

## Before vs After: entry point construction

### 0.7.0 (old)

```kotlin
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.WalletMetadata

val walletMetadata: WalletMetadata = /* build/parse metadata */

val openID4VP = OpenID4VP(
    traceabilityId = "trace-id",
    walletMetadata = walletMetadata
)
```

Reference: `OpenID4VP.kt` (v0.7.0)

### 0.8.0 (new)

```kotlin
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.WalletConfig

val walletConfig = WalletConfig(
    trustedVerifiers = trustedVerifiers,
    // Optional: set capability fields explicitly or keep defaults.
)

val openID4VP = OpenID4VP(
    traceabilityId = "trace-id",
    walletConfig = walletConfig
)
```

Reference: `OpenID4VP.kt` (current)

### Mapping `WalletMetadata` -> `WalletConfig`

`WalletConfig` now accepts wallet capability parameters directly. For migration, each parameter below is equivalent to the `WalletMetadata` parameter serving the same purpose.

| WalletConfig parameter                      | WalletMetadata equivalent                   | Purpose                                       |
|---------------------------------------------|---------------------------------------------|-----------------------------------------------|
| `vpFormatsSupported`                        | `vpFormatsSupported`                        | Advertised VP/VC format capabilities          |
| `clientIdPrefixesSupported`                 | `clientIdPrefixesSupported`                 | Supported `client_id` prefix schemes          |
| `requestObjectSigningAlgValuesSupported`    | `requestObjectSigningAlgValuesSupported`    | Supported request object signature algorithms |
| `authorizationEncryptionAlgValuesSupported` | `authorizationEncryptionAlgValuesSupported` | Supported JWE key management algorithms       |
| `authorizationEncryptionEncValuesSupported` | `authorizationEncryptionEncValuesSupported` | Supported JWE content encryption algorithms   |
| `responseTypesSupported`                    | `responseTypeSupported`                     | Supported authorization response types        |

Additional `WalletConfig` fields in 0.8.0:
- `trustedVerifiers` (default verifier list)
- `isPresentationDefinitionUriSupported`
- `supportedRequestUriMethods`

---

## Before vs After: `authenticateVerifier(...)`

### What stays conceptually the same
- You still validate a verifier authorization request and get back an `AuthorizationRequest`.
- `shouldValidateClient` is still present (and defaults to `true`).

### What changes in practice

1. **Trusted verifier handling moves to wallet config**
   - Keep trusted verifiers in `walletConfig.trustedVerifiers` for migrated 0.8.0 flow.
   - In this migrated flow, `authenticateVerifier(authorizationRequest: Map<String, Any>, ...)` is documented without a `trustedVerifiers` argument (do not pass it in the call).

2. The deprecated 0.7.0 overload that accepted `walletMetadata` in the `authenticateVerifier` call is removed from the entry point API in 0.8.0.

### 0.7.0 call (old)

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
    trustedVerifiers = trustedVerifiers,
    shouldValidateClient = true
)
```

### 0.8.0 call (new, URL-encoded)

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
    shouldValidateClient = true
)
```

### 0.8.0 call (new, map)

```kotlin
val authorizationRequest = openID4VP.authenticateVerifier(
    authorizationRequest = authorizationRequestMap,
    shouldValidateClient = true
)
```

Reference: `OpenID4VP.kt` (current)

---

## Before vs After: `constructUnsignedVPToken(...)` (biggest change)

### Old behavior (0.7.0)

In 0.7.0, the entry point exposed older flows where:
- you passed a `verifiableCredentials` map
- and optionally provided signing inputs like `holderId` / `signatureSuite`
- and the method returned an encoded structure that downstream code had to interpret

### New behavior (0.8.0)

In 0.8.0, `constructUnsignedVPToken` returns **a typed list of signing work units**:

```kotlin
val unsignedVPTokens: List<UnsignedVPToken> =
    openID4VP.constructUnsignedVPToken(selectedCredentials)
```

Where `selectedCredentials` is:
- `Map<String, List<Credential>>`
- key: `input_descriptor.id` (Presentation Definition flow) or `credential_query.id` (DCQL flow)
- value: selected credential list where each `Credential` has:
  - `format: FormatType`
  - `data: Any` (VC payload, wallet-specific)
  - `credentialId: String`

Example (dummy data):

```kotlin
val selectedCredentials: Map<String, List<Credential>> = mapOf(
    // Presentation Definition input descriptor id
    "age_descriptor" to listOf(
        Credential(
            format = FormatType.LDP_VC,
            data = mapOf(
                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                "type" to listOf("VerifiableCredential", "AgeCredential"),
                "credentialSubject" to mapOf(
                    "id" to "did:example:holder-001",
                    "ageOver18" to true
                )
            ),
            credentialId = "cred-age-001"
        )
    ),
    // DCQL credential query id
    "email_query" to listOf(
        Credential(
            format = FormatType.JWT_VC_JSON,
            data = "<compact-jwt-vc>",
            credentialId = "cred-email-777"
        )
    )
)
```

`holderId` and `signatureSuite` are removed from this input flow in 0.8.0 because LDP VP construction now derives holder identity from `credentialSubject.id` and uses `JsonWebSignature2020` as signature suite.

Each `UnsignedVPToken` provides:
- `format: FormatType`
- `holderKeyReference: String`
- `signatureAlgorithm: String`
- `dataToSign: ByteArray`

So your wallet integration becomes:

```kotlin
val vpTokenSigningResults: List<VPTokenSigningResult> =
    unsignedVPTokens.map { token ->
        // Wallet-specific signing implementation:
        val signatureBytes: ByteArray =
            walletKeyManager.sign(
                token.dataToSign,
                token.holderKeyReference,
                token.signatureAlgorithm
            )

        VPTokenSigningResult(signedData = signatureBytes)
    }
```

References:
- `OpenID4VP.kt` (current): `constructUnsignedVPToken(selectedCredentials: Map<String, List<Credential>>)`
- `authorizationResponse/unsignedVPToken/UnsignedVPToken.kt`
- `authorizationResponse/vpTokenSigningResult/VPTokenSigningResult.kt`

---

## Before vs After: `constructVPResponse(...)`

### 0.7.0 (old)

```kotlin
val response: Map<String, Any> = openID4VP.constructVPResponse(
    vpTokenSigningResults = /* older signing result structure */
)
```

### 0.8.0 (new)

```kotlin
val response: Map<String, Any> = openID4VP.constructVPResponse(
    vpTokenSigningResults = vpTokenSigningResults
)
```

Signature (0.8.0):
- `constructVPResponse(vpTokenSigningResults: List<VPTokenSigningResult>): Map<String, Any>`

Behavior notes (0.8.0):
- if an `OpenID4VPExceptions` happens during construction, the method returns an error info map (`constructErrorInfo(exception)`) instead of throwing at the call site.

---

## DCQL helper: `getMatchingCredentials(...)` from `DCQLHelper`

In 0.8.0, DCQL credential matching is exposed as a helper on `DCQLHelper`:

```kotlin
import io.mosip.openID4VP.evaluator.dcql.DCQLHelper

val dcqlHelper = DCQLHelper()
val matchingResult = dcqlHelper.getMatchingCredentials(
    inputCredentials = walletAvailableCredentials,
    dcqlQuery = authorizationRequest.dcqlQuery
)
```

Use this helper to evaluate a full list of credentials available in the wallet and identify which credentials satisfy each DCQL `credential_query`.

This is especially useful before calling `constructUnsignedVPToken(...)`, so the selected credentials map can be built with matching credentials for DCQL query ids.

Reference:
- TODO: Add a link to readme section on DCQL flow once the README is updated.

---

## Before vs After: `sendVPResponseToVerifier(...)`

### 0.7.0 (old)

```kotlin
val verifierResponse: VerifierResponse = openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults = /* older signing result structure */
)
```

### 0.8.0 (new)

```kotlin
val verifierResponse: VerifierResponse = openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults = vpTokenSigningResults
)
```

Signature (0.8.0):
- `sendVPResponseToVerifier(vpTokenSigningResults: List<VPTokenSigningResult>): VerifierResponse`

---

## Removed entry-point methods from 0.7.0 (update your call sites)

> 🚨 **Notice**
> 
> All deprecated entry-point APIs from 0.7.0 are removed in 0.8.0.

The current entry point in 0.8.0 only exposes the following public methods:
- `authenticateVerifier(...)` (URL-encoded and Map variants)
- `constructUnsignedVPToken(...)`
- `constructVPResponse(...)`
- `sendVPResponseToVerifier(...)`
- `constructErrorInfo(...)`
- `sendErrorInfoToVerifier(...)`

For DCQL matching, use helper class `DCQLHelper`:
- `getMatchingCredentials(inputCredentials: List<Credential>, dcqlQuery: DCQLQuery): MatchingCredentialsResult`

If your 0.7.0 integration used any of these removed APIs, replace them with the closest 0.8.0 equivalent:
- `constructUnsignedVPTokenV2(...)` -> use `constructUnsignedVPToken(...)` and the new `UnsignedVPToken` signing flow
- `constructVPResponseV2(...)` -> use `constructVPResponse(...)`
- `shareVerifiablePresentation(...)` / `sendErrorToVerifier(...)` / `constructVerifiablePresentationToken(...)` -> use the newer error/VP flow:
  - `constructVPResponse(...)` + `sendVPResponseToVerifier(...)`
  - `constructErrorInfo(...)` + `sendErrorInfoToVerifier(...)`

---

## Minimal working example in 0.8.0

```kotlin
val walletConfig = WalletConfig(
    trustedVerifiers = trustedVerifiers,
    // optionally: set vpFormatsSupported, clientIdPrefixesSupported, etc.
)

val openID4VP = OpenID4VP(
    traceabilityId = "trace-id",
    walletConfig = walletConfig
)

val authorizationRequest = openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
    shouldValidateClient = true
)

val selectedCredentials: Map<String, List<Credential>> = mapOf(
    "age_descriptor" to listOf(
        Credential(
            format = FormatType.LDP_VC,
            data = mapOf(
                "credentialSubject" to mapOf("id" to "did:example:holder-001", "ageOver18" to true)
            ),
            credentialId = "cred-age-001"
        )
    )
)
val unsignedVPTokens = openID4VP.constructUnsignedVPToken(selectedCredentials)

val signingResults = unsignedVPTokens.map { token ->
    val signatureBytes = walletKeyManager.sign(
        token.dataToSign,
        token.holderKeyReference,
        token.signatureAlgorithm
    )
    VPTokenSigningResult(signedData = signatureBytes)
}

val verifierResponse = openID4VP.sendVPResponseToVerifier(signingResults)
```

---

## TODO: align README docs with this migration guide

- Update this appendix with links to the relevant sections of the README once the README is updated to reflect the 0.8.0 changes.

---

## Appendix: where to look for updated types

- Entry point:
  - `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/OpenID4VP.kt`
- Wallet config/capabilities:
  - `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationRequest/WalletConfig.kt`
  - `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationRequest/WalletMetadata.kt`
- Signing work units:
  - `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/unsignedVPToken/UnsignedVPToken.kt`
  - `kotlin/openID4VP/src/commonMain/kotlin/io/mosip/openID4VP/authorizationResponse/vpTokenSigningResult/VPTokenSigningResult.kt`

