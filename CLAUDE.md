# OVP Spec V1 Support - Porting Swift PR #111 to Kotlin

## Agentic Guidelines
- Port source files only (no tests) — commit in logical chunks
- Follow existing Kotlin codebase patterns (kotlinx.serialization, Jackson annotations)
- Keep backward compatibility with deprecated constructors where possible
- The directory path uses `openId4VP` (case-sensitive) but git sees `openID4VP`
- Talisman pre-commit hook may flag false positives — add checksums to `.talismanrc`
- When in doubt on Swift→Kotlin mapping decisions, ask the user

## Summary
Port Swift iOS PR (inji/inji-openid4vp-ios-swift#111) changes to this Kotlin multiplatform project.
The PR adds support for OVP spec version 1.0 alongside draft-23.

## Completed Changes

### Constants (New/Modified) ✅
- [x] Add `SpecVersion` enum (DRAFT_23, V1)
- [x] Add `ClientIdPrefix` enum (PRE_REGISTERED, REDIRECT_URI, DECENTRALIZED_IDENTIFIER)
- [x] Add `ProofType` enum
- [x] Update `AuthorizationRequestFieldConstants` - remove clientIdScheme, add dcqlQuery
- [x] Make `ClientIdScheme` internal

### Verifier ✅
- [x] Add specVersion field to Verifier (default V1)

### Wallet Metadata ✅
- [x] VPFormatSupported sealed interface with LdpVcFormatSupported, MsoMdocVcFormatSupported, SdJwtVcFormatSupported
- [x] WalletMetadata restructured - clientIdPrefixesSupported, removed presentationDefinitionURISupported
- [x] WalletMetadata.encode(specVersion) for version-aware encoding
- [x] WalletMetadataUtils parse helpers
- [x] WalletMetadataDefaults updated

### ClientMetadata ✅
- [x] ClientMetadataDraft23 (old format with vp_formats, authorization_encrypted_response_alg/enc)
- [x] ClientMetadata v1 (vp_formats_supported, encrypted_response_enc_values_supported)
- [x] ClientMetadataSpecVersionHandler for version-aware parsing

### Authorization Request ✅
- [x] AuthorizationRequest refactored to open base class
- [x] AuthorizationPresentationExchangeRequest (draft-23 with PresentationDefinition + ClientMetadataDraft23)
- [x] AuthorizationDcqlRequest (v1 with ClientMetadata)
- [x] handler.handle() replaces processAndValidateAuthorizationRequestParameter

### Authorization Request Handlers ✅
- [x] ClientIdPrefixBasedAuthorizationRequestHandler with SpecVersionHandler
- [x] DecentralizedIdentifierPrefixAuthorizationRequestHandler (replaces Did)
- [x] RedirectUriPrefixAuthorizationRequestHandler (replaces RedirectUri)
- [x] PreRegisteredSchemeAuthorizationRequestHandler updated
- [x] AuthorizationRequestUtils rewritten (extractClientIdPrefix, findSpecVersion, etc.)

### Authorization Response ✅
- [x] AuthorizationResponse sealed class with PresentationExchange and Dcql variants
- [x] AuthorizationResponseHandler takes walletMetadata parameter

### Response Mode Handlers ✅
- [x] DirectPostJwtResponseModeHandler with SpecVersionHandler for encryption
- [x] Validate overloads for ClientMetadataDraft23
- [x] DirectPostResponseModeHandler updated

### OpenID4VP Main Class ✅
- [x] Pass walletMetadata to AuthorizationResponseHandler

### JWE & Decryption ✅
- [x] JWE Concat KDF (deriveKey with algorithm, apu, apv) - implemented manual `X25519KeyAgreement`
- [x] JWK thumbprint BSTR utility in `CborUtils.kt`
- [x] JWE decryption support in `JWEHandler.kt`
- [x] Updated `generateNonce` to match Swift implementation (Base64URL encoded random bytes)

## Remaining (not done this session)
- [ ] Tests

