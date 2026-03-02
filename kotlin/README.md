# INJI-OpenID4VP


## 🚨 Breaking Changes

### From Version `release-0.4.x` onward:

### API contract changes
This library has undergone some changes in its API contract.

#### 1. Instantiation of OpenID4VP
- The OpenID4VP class is now initialized with `traceabilityId` and `walletMetadata` parameter, which is used to track the traceability of the requests and responses.

```kotlin
val openID4VP = OpenID4VP(traceabilityId = "trace-id", walletMetadata = walletMetadata)
```

#### 2. Construction of WalletMetadata
- The WalletMetdata construction has now been simplified. You can create a WalletMetadata object with the required parameters exposed as constants.
- In detail,
- `WalletMetadata` is now a struct that contains the following properties:
    - `presentationDefinitionURISupported`: Boolean
    - `vpFormatsSupported`: Map<String: VPFormatSupported>
    - `clientIdSchemesSupported`: List<ClientIdScheme>?
    - `requestObjectSigningAlgValuesSupported`: List<RequestSigningAlgorithm>?
    - `authorizationEncryptionAlgValuesSupported`: List<KeyManagementAlgorithm>?
    - `authorizationEncryptionEncValuesSupported`: List<ContentEncryptionAlgorithm>?

```kotlin
val walletMetadata = WalletMetadata(
    presentationDefinitionURISupported = true,
    vpFormatsSupported = mapOf(
        FormatType.LDP_VC to VPFormatSupported(
            algValuesSupported = listOf("EdDSA")
        )
    ),
    clientIdSchemesSupported = listOf(ClientIdScheme.REDIRECT_URI, ClientIdScheme.PRE_REGISTERED),
    requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
    authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
    authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
)
```

3. The shouldValidateClient parameter in authenticateVerifier now defaults to true.
- If your integration previously relied on it being false, you must now explicitly pass false to preserve the old behavior.
- Example (updated usage)
```kotlin
val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
                    trustedVerifiers = trustedVerifiers,
                    shouldValidateClient = true
                )
```


#### ❗ Required Update in Imports

Replace:

```kotlin
import io.mosip.openID4VP.dto.Verifier;
import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata;
```

With:

```kotlin
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata;
```

## API contract changes

- This library has undergone significant changes in its API contract. The new API contracts are designed to be more flexible and extensible, allowing for support of multiple verifiable credential formats. The changes are discussed in the [API section](#apis) below.
- Backward compatibility of all the APIs with the previous version of the library has been maintained.


## **Introduction**

inji-openid4vp is an implementation of OpenID for Verifiable Presentations written in kotlin. It supports sharing of verifiable credentials with verifiers using the OpenID4VP protocol.

Inji-OpenID4VP library is Kotlin Multiplatform Library which generates both AAR and JAR files for Android and Java-based projects respectively.

The library validates the client_id and client_id_scheme parameters in the authorization request according to the relevant specification.
- If the client_id_scheme parameter is included in the authorization request, the request is treated as conforming to Draft 21, and validation is performed accordingly.
- If the client_id_scheme parameter is not included, the request is interpreted as following Draft 23, and validation is applied based on that specification.

## **Supported Credential Formats**
The following credential formats are supported for sharing:
- Ldp Vc (**ldp_vc**) : Implemented using [Specification-21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) and [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html)
- Mso-Mdoc Vc (**mso_mdoc**): Implemented using [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) and [ISO/IEC TS 18013-7](https://www.iso.org/standard/82772.html)
- Sd-jwt Vc (**dc+sd-jwt**,**vc+sd-jwt**): Implemented using [draft-ietf-oauth-sd-jwt(vc)](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html),[draft-ietf-oauth-sd-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/) and [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html)
----
#### SD-JWT Specific Notes



- Only SD-JWT VCs that include a `cnf` (confirmation) claim with a `kid`  are supported for signing and sharing.
- Supported algorithms for `cnf.kid` as `did:jwk` (used in holder binding):
    - `ES256`
    - `EdDSA`
- If an SD-JWT VC does **not** include a `cnf`, no Key Binding JWT (KB-JWT) is created for that credential.
    - These credentials are **not sent to the wallet** for signing and will be skipped from `uuidToUnsignedKBT`.

🔐 **_sd_alg Support:**
- Supported `_sd_alg` values for SD-JWT disclosures:
    - `sha-256`
    - `sha-384`
    - `sha-512`
- If the SD-JWT VC contains disclosures hashed with **unsupported or mismatched `_sd_alg`**, an exception will be thrown.
  The `_sd_alg` is required for generating `sd_hash` inside the KB-JWT and must match the hashing algorithm used in the disclosures.

---


## **Table of Contents**

- [Installation](#installation)
- [Integration](#integration)
- [Package Structure](#package-structure)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructunsignedvptoken)
  - [constructUnsignedVPTokenV2](#constructunsignedvptokenv2)
  - [constructVPResponse](#constructvpresponse)
  - [constructVPResponseV2](#constructvpresponsev2)
  - [sendVPResponseToVerifier](#sendvpresponsetoverifier)
  - [constructErrorInfo](#constructerrorinfo)
  - [sendErrorInfoToVerifier](#senderrorinfotoverifier)


## Installation

#### For Android Based Projects

```
implementation "io.inji:inji-openid4vp-aar:0.7.0"
```

#### For Java-based Projects

```
implementation "io.inji:inji-openid4vp-jar:0.7.0"
```

## Create instance of OpenID4VP library to invoke its methods

```kotlin
val openID4VP = OpenID4VP(traceabilityId = "trace-id", walletMetadata = walletMetadata)
```

###### Parameters
| Name           | Type           | Description                                                                                                     |
|----------------|----------------|-----------------------------------------------------------------------------------------------------------------|
| traceabilityId | String         | Unique identifier for tracking requests and responses.                                                          |
| walletMetadata | WalletMetadata | Metadata which wallet supports, such that client-id-scheme support, vp format support, proof type support, etc. |

## Integration
- To integrate the inji-openid4vp library into your Android application, there is a sample application created in `kotlin/sampleovpwallet` directory. This sample app demonstrates how to use the library to authenticate Verifiers, construct unsigned Verifiable Presentation (VP) tokens, and share them with Verifiers.
- For more details refer to [README](sampleovpwallet/README.md) of the sample application.

## Package Structure
This library has KMP (Kotlin Multiplatform) structure.The encoding and decoding logic is mainly segregated into androidMain and jvmMain source sets respectively. The commonMain source set contains the core logic of the library which is platform agnostic.
Below is the high-level package structure of the `commonMain` source set:
```
io.mosip.openID4VP/
├── OpenID4VP.kt                    # Main entry point: exposes public APIs
│
├── authorizationRequest/           # Authorization request parsing + validation
│   ├── AuthorizationRequest.kt     # Parses + holds request parameters
│   ├── WalletMetadata.kt           # wallet-specific metadata
│   ├── authorizationRequestHandler/
│   │   ├── ClientIdSchemeBasedAuthorizationRequestHandler.kt  # Strategy base class
│   │   └── types/                  # Handler strategies for DID, URI, etc.
│   │       ├── DidSchemeAuthorizationRequestHandler.kt
│   │       ├── PreRegisteredSchemeAuthorizationRequestHandler.kt
│   │       └── RedirectUriSchemeAuthorizationRequestHandler.kt
│   ├── clientMetadata/             #  Client metadata & JWKS-related
│   │   ├── ClientMetadata.kt
│   │   ├── Jwk.kt
│   │   └── Jwks.kt
│   └── presentationDefinition/    # Presentation definition parsing + validation
│
├── authorizationResponse/          # Authorization response construction
│   ├── AuthorizationResponse.kt
│   ├── AuthorizationResponseHandler.kt
│   ├── presentationSubmission/
│   │   └── PresentationSubmission.kt + DescriptorMap.kt
│   ├── unsignedVPToken/            # Pre-signature VP tokens: sent to wallet
│   │   └── types/
│   │       ├── ldp/    ➝ UnsignedLdpVPToken.kt
│   │       ├── mdoc/   ➝ UnsignedMdocVPToken.kt
│   │       └── sdJwt/  ➝ UnsignedSdJwtVPToken.kt
│   ├── vpToken/                    # Final signed tokens
│   │   └── types/
│   │       ├── ldp/    ➝ LdpVPToken.kt
│   │       ├── mdoc/   ➝ MdocVPToken.kt
│   │       └── sdJwt/  ➝ SdJwtVPToken.kt
│   └── vpTokenSigningResult/       # Signature result for all formats: coming from wallet
│       └── types/
│           ├── ldp/    ➝ LdpVPTokenSigningResult.kt
│           ├── mdoc/   ➝ MdocVPTokenSigningResult.kt
│           └── sdJwt/  ➝ SdJwtVPTokenSigningResult.kt
│
├── jwt/                            # JWS/JWE operations
│   ├── jwe/
│   │   └── JWEHandler.kt + EncryptionProvider.kt
│   └── jws/
│       └── JWSHandler.kt
│
├── responseModeHandler/            # Direct-post/Direct-postJWT modes
│   ├── ResponseModeBasedHandler.kt
│   └── types/
│       ├── DirectPostResponseModeHandler.kt
│       └── DirectPostJwtResponseModeHandler.kt
│
├── common/                         #  Shared helpers/utilities
│   └── (Utils.kt, Encoder.kt, Decoder.kt, etc.)
│
├── constants/                      # Enum-style constants
│   └── (FormatType.kt, VPFormatType.kt, SigningAlgorithm.kt, etc.)
│
├── networkManager/                 # HTTP request layer abstraction
│   └── NetworkManagerClient.kt + Exceptions
│
├── exceptions/                     # Error definitions
│   └── OpenID4VPExceptions.kt
```

## APIs

### authenticateVerifier

- Validates the Verifier's Authorization request received from the Wallet and returns the valid Authorization request object.
- This method is overloaded to support different ways of Verifier's Authorization request data either as encoded string or as Map of parameters.
- This method does the following:
    - Receives a list of trusted verifiers & Verifier's Authorization request from consumer (of the library, example - Wallet app).
    - Takes an optional boolean to toggle the client validation.
    - Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId if clientId is identified to have `pre_registered` clientId scheme.
    - If the data contains `request_uri` and `request_uri_method` as post, then the wallet metadata is shared in the request body while making an api call to request_uri for fetching authorization request.
    - The library also validates the incoming authorization request with the wallet metadata passed during the instantiation of OpenID4VP class.

**Note 1:** Wallet can send the entire metadata, library will customize it as per authorization request client_id_scheme. Eg - in case pre-registered, library modifies wallet metadata to be sent without request object signing info properties as specified in the specification.

**Note 2:** Currently the library does not support limit disclosure for any format of VC. It will throw an error if the request contains `presentation_definition` or `presentation_definition_uri` with `input_descriptors` and `limit_disclosure` set to required.

#### Overloads

##### 1. Validates the Authorization request received as URL Encoded string

```kotlin
    val authorizationRequest : AuthorizationRequest = openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>, shouldValidateClient: Boolean)
```

##### 2. Validates the Authorization request received as Map of parameters

```kotlin
    val authorizationRequest : AuthorizationRequest = openID4VP.authenticateVerifier(authorizationRequest: Map<String, Any>, trustedVerifiers: List<Verifier>, shouldValidateClient: Boolean)
```

``` kotlin
//NOTE: New API contract
 val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                                    urlEncodedAuthorizationRequest: String, 
                                    trustedVerifiers: List<Verifier>,
                                    shouldValidateClient: Boolean = false)
                                    
//NOTE: Old API contract (with walletMetadata parameter) for backward compatibility
 val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                                    urlEncodedAuthorizationRequest: String, 
                                    trustedVerifiers: List<Verifier>,
                                    shouldValidateClient: Boolean = false,
                                    walletMetadata: WalletMetadata?)
```

#### Request Parameters

| Name                           | Type             | Required | Default Value | Description                                                                                                                                                                                                                                    |
|--------------------------------|------------------|----------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest | String           | Yes      | N/A           | URL encoded query parameter string containing the Verifier's authorization request                                                                                                                                                             |
| authorizationRequest           | [String : Any]   | Yes      | N/A           | authorization request                                                                                                                                                                                                                          |
| trustedVerifiers               | List\<Verifier\> | Yes      | N/A           | A list of trusted Verifier objects each containing a clientId, responseUri, jwksUri and allowUnsignedRequest which is used to verify if the Authorization Request if from known Verifier (refer [here](#verifier-parameters) for more details) |
| walletMetadata (deprecated*)   | WalletMetadata?  | No       | N/A           | Nullable WalletMetadata to be shared with Verifier (Note: Available in Old deprecated API contract, walletMetadata is now passed as a constructor parameter of OpenID4VP class)                                                                |
| shouldValidateClient           | Boolean          | No       | true          | Boolean to toggle client validation for pre-registered client id scheme                                                                                                                                                                        |

#### Response Parameters


| Type                 | Description                                 |
|----------------------|---------------------------------------------|
| AuthorizationRequest | The validated Authorization Request object. |

Example AuthorizationRequest object:

```kotlin
val authorizationRequest = AuthorizationRequest(
    clientId = "https://mock-verifier.com",
    responseType = "vp_token",
    responseMode = "direct_post",
    presentationDefinition = PresentationDefinition(
        id = "649d581c-f891-4969-9cd5-2c27385a348f",
        inputDescriptors = listOf(
            InputDescriptor(
                id = "id card credential",
                format = mapOf(
                    "ldp_vc" to mapOf(
                        "proof_type" to listOf("Ed25519Signature2018")
                    )
                ),
                constraints = Constraints(
                    fields = listOf(
                        Fields(path = listOf("\$.type"))
                    )
                )
            )
        )
    ),
    responseUri = "https://mock-verifier.com",
    redirectUri = null,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = ClientMetadata(
        clientName = "Requester name",
        logoUri = "<logo_uri>",
        authorizationEncryptedResponseAlg = "ECDH-ES",
        authorizationEncryptedResponseEnc = "A256GCM",
        vpFormats = mapOf(
            "ldp_vc" to mapOf(
                "algValuesSupported" to listOf("Ed25519Signature2018", "Ed25519Signature2020")
            )
        ),
        jwks = Jwks(
            keys = listOf(
                Jwk(
                    kty = "OKP",
                    crv = "X25519",
                    use = "enc",
                    x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    alg = "ECDH-ES",
                    kid = "ed-key1"
                )
            )
        )
    )
)
```
#### Example usage

```kotlin
val encodedAuthorizationRequest = ".../authorize?response_type=vp_token&client_id=redirect_uri%3Ahttps%3..."
val trustedVerifiers = listOf(Verifier("https://verify.env1.net",listOf("https://verify.env1.net/responseUri")))
val walletMetadata = WalletMetadata(
    presentationDefinitionURISupported = true,
    vpFormatsSupported = mapOf(
        FormatType.LDP_VC to VPFormatSupported(
            algValuesSupported = listOf("EdDSA")
        )
    ),
    clientIdSchemesSupported = listOf(ClientIdScheme.REDIRECT_URI, ClientIdScheme.PRE_REGISTERED),
    requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
    authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
    authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
)

// Usage with URL Encoded Authorization Request

val urlEncodedAuthorizationRequest: String = """
        openid4vp://authorize?
          client_id=did%3Aweb%verifier.inji.net%3Av1%3Averify
          &client_metadata=...
          &request_uri=https%3A%2F%2Fclient.example.org%2Frequest%2Fvapof4ql2i7m41m68uep
          &request_uri_method=post HTTP/1.1
        """

val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                    urlEncodedAuthorizationRequest = urlEncodedAuthorizationRequest,
                    trustedVerifiers = trustedVerifiers,
                    shouldValidateClient = true
                )

// Usage with Map of parameters Authorization Request

val authorizationRequestMap: Map<String, Any> = mapOf(
    "client_id" to "mock-client",
    "response_type" to "vp_token",
    "response_mode" to "direct_post",
    "presentation_definition" to mapOf(/*...*/),
    "nonce" to "random-nonce",
    "state" to "random-state",
    "redirect_uri" to "https://mock-verifier.com/response"
)

val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
    authorizationRequest = authorizationRequestMap,
    trustedVerifiers = trustedVerifiers,
    shouldValidateClient = true
)
```

#### WalletMetadata Parameters

| Parameter                                 | Type                                 | Required   | Default Value    | Description                                                                                      |
|-------------------------------------------|--------------------------------------|------------|------------------|--------------------------------------------------------------------------------------------------|
| presentationDefinitionURISupported        | Boolean                              | No         | true             | Indicates whether the wallet supports `presentation_definition_uri`.                             |
| vpFormatsSupported                        | Map\<FormatType: VPFormatSupported\> | Yes        | N/A              | A dictionary specifying the supported verifiable presentation formats and their algorithms.      |
| clientIdSchemesSupported                  | List\<ClientIdScheme\>               | No         | "pre-registered" | A list of supported client ID schemes.                                                           |
| requestObjectSigningAlgValuesSupported    | List\<RequestSigningAlgorithm\>?     | No         | null             | A list of supported algorithms for signing request objects.                                      |
| authorizationEncryptionAlgValuesSupported | List\<KeyManagementAlgorithm\>?      | No         | null             | A list of supported algorithms for encrypting authorization responses.                           |
| authorizationEncryptionEncValuesSupported | List\<ContentEncrytionAlgorithm\>?   | No         | null             | A list of supported encryption methods for authorization responses.                              |

#### Verifier Parameters

Each Verifier object in the trustedVerifiers list should contain the following properties:

| Parameter            | Type           | Required | Default Value | Description                                                                                                                                                                                       |
|----------------------|----------------|----------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| clientId             | String         | Yes      | N/A           | The unique identifier for the Verifier.                                                                                                                                                           |
| responseUri          | List\<String\> | Yes      | N/A           | A list of URIs where the Verifier can receive responses from the wallet.                                                                                                                          |
| jwksUri              | String         | No       | null          | URI value of the Verifier's hosted public key. This will be used to verify the signed Authorization Request. If this is not available Verifier's signed Authorization request cannot be verified. |
| allowUnsignedRequest | Boolean        | No       | false         | Accepts unsigned requests from the Verifier. If `shouldValidateClient` is false, unsigned requests are still not allowed.                                                                         |

#### Exceptions

1. DecodingException is thrown when there is an issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if
    * query params are not present in the Request
    * there is an issue while extracting the params
    * both presentation_definition and presentation_definition_uri are present in Request
    * both presentation_definition and presentation_definition_uri are not present in Request
3. MissingInput exception is thrown if any of required params are not present in Request
4. InvalidInput exception is thrown if any of required params value is empty or null
5. InvalidVerifier exception is thrown if the received request client_iD & response_uri are not matching with any of the trusted verifiers
6. JWTVerification exception is thrown if there is any error in extracting public key, kid or signature verification failure.
7. InvalidData exception is thrown if
    - `response_mode` is not supported
    - For `direct_post.jwt` response mode
        - client_metadata is not available
        - unable to find the public key JWK from the `jwks` of `client_metadata` as per the provided algorithm in `client_metadata`
    - `publicKeyMultibase` is null or empty
8. UnsupportedPublicKeyType exception is thrown when the public key type is not `publicKeyMultibase`.
9. PublicKeyExtractionFailed exception is thrown when there are any errors in extracting the public key from verification method

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### constructUnsignedVPToken
- This method creates unsigned Verifiable Presentation (VP) tokens from a collection of Verifiable Credentials. It:
    - Takes credentials organized by input descriptor IDs and formats along with the holder's identifier, and the signature suite to be used for signing the VP tokens.
    - Creates format-specific VP tokens (supporting JSON-LD and  mDOC formats)
    - Returns a map of unsigned VP tokens organized by format type
- The tokens returned are ready for digital signing **to be signed by wallet** before being shared with verifiers in an OpenID4VP flow.

```kotlin
    //NOTE: New API contract
    val unsignedVPTokens : Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(Map<String, Map<FormatType, List<Any>>>)

    //NOTE: Old API contract for backward compatibility
    val unsignedVPTokens : String = openID4VP.constructUnsignedVPToken(Map<String, List<String>>)
```

#### Request Parameters

| Name                  | Type                                    | Description                                                                                                                                    |
|-----------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| verifiableCredentials | Map<String, Map<FormatType, List<Any>>> | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |


#### Response Parameters
```kotlin
//NOTE: New API contract Response
val unsignedLdpVpTokens: Map<FormatType, UnsignedVPToken> = mapOf(
    FormatType.LDP_VC to UnsignedLdpVPToken(
        dataToSign = "base64EncodedCanonicalisedData", // This should be the actual base64 encoded canonicalized data of the VP token
    ),
    FormatType.MSO_MDOC to UnsignedMdocVPToken(
        docTypeToDeviceAuthenticationBytes = mapOf(
            "org.iso.18013.5.1.mDL" to "<docTypeToDeviceAuthenticationBytes>" // This should be the actual base64 encoded bytes of the device authentication
        )
    ),
    FormatType.VC_SD_JWT to UnsignedSdJwtVPToken(
        uuidToUnsignedKBT = mapOf(
            "uuid" to "<unsignedKBT(<kbtHeader>.<kbtPayload>)>" // This should be the actual unsigned KBT (header + payload)
        )
    ),
    FormatType.DC_SD_JWT to UnsignedSdJwtVPToken(
        uuidToUnsignedKBT = mapOf(
            "uuid" to "<unsignedKBT(<kbtHeader>.<kbtPayload>)>" // This should be the actual unsigned KBT (header + payload)
        )
    )
)

//NOTE: Old API contract Response
val unsignedVPToken: String = """
    {
          "@context": ["context-url"],
          "type": ["type"],
          "verifiableCredential": [
            "ldpCredential1",
            "ldpCredential2"
          ],
          "id": "id",
          "holder": "holder"
    }
"""
```


#### Example usage

```kotlin
 val unsignedVPTokens : Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(
            verifiableCredentials = mapOf(
                "input_descriptor_id" to mapOf(
                    FormatType.LDP_VC to listOf(
                        <ldp-vc-json>,
                    )
                ),
                "input_descriptor_id" to mapOf(
                    FormatType.MSO_MDOC to listOf(
                        "credential2",
                    )
                ),
                "input_descriptor_id" to mapOf(
                    FormatType.VC_SD_JWT to listOf(
                        "credential3",
                    )
                ),
                "input_descriptor_id" to mapOf(
                    FormatType.DC_SD_JWT to listOf(
                        "credential4",
                    )
                ),
            )
        )
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if provided verifiable credentials list is empty

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.



### constructUnsignedVPTokenV2
- This method creates a flattened list of unsigned VP tokens from a collection of Verifiable Credentials, where each token contains the holder's key reference and signature algorithm required for signing.
- It takes credentials organized by input descriptor IDs and formats, processes them, and returns a list of `UnsignedVPTokenV2` objects, each containing:
    - The credential format type
    - Holder key reference
    - Signature algorithm to be used
    - Data that needs to be signed
- This API simplifies the signing process by providing all necessary information upfront, allowing the wallet to sign each token independently without needing to understand format-specific details.

```kotlin
    val unsignedVPTokens : List<UnsignedVPTokenV2> = openID4VP.constructUnsignedVPTokenV2(
        verifiableCredentials: Map<String, Map<FormatType, List<Any>>>,
        holderId: String? = null,
        signatureSuite: String? = null
    )
```

#### Request Parameters

| Name                  | Type                                    | Required | Default Value | Description                                                                                                                                         |
|-----------------------|-----------------------------------------|----------|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| verifiableCredentials | Map<String, Map<FormatType, List<Any>>> | Yes      | N/A           | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials      |
| holderId              | String?                                 | No       | null          | The holder's identifier (e.g., DID). Required for LDP_VC format credentials                                                                         |
| signatureSuite        | String?                                 | No       | null          | The signature suite/algorithm to be used for signing LDP credentials (e.g., "RsaSignature2018", "Ed25519Signature2018"). Required for LDP_VC format |


#### Response Parameters

The method returns a `List<UnsignedVPTokenV2>` where each `UnsignedVPTokenV2` object contains:

| Property           | Type       | Description                                                                                                                                           |
|--------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| format             | FormatType | The credential format type (LDP_VC, MSO_MDOC, VC_SD_JWT, or DC_SD_JWT)                                                                                |
| holderKeyReference | String     | Reference to the holder's key - DID for LDP credentials, key identifier (kid) for SD-JWT, Base64 encoded key for `mso_mdoc` credentials               |
| signatureAlgorithm | String     | The signature algorithm to use (e.g., "RsaSignature2018" for LDP, "ES256" for mDOC, "ES256" for SD-JWT)                                               |
| dataToSign         | String     | The actual data that needs to be signed - base64 encoded canonicalized data for LDP, unsigned KB-JWT for SD-JWT, device authentication bytes for mDOC |


#### Example usage

```kotlin
 val unsignedVPTokens : List<UnsignedVPTokenV2> = openID4VP.constructUnsignedVPTokenV2(
            verifiableCredentials = mapOf(
                "input_descriptor_id_1" to mapOf(
                    FormatType.LDP_VC to listOf(
                        "<ldp-vc-json>",
                    )
                ),
                "input_descriptor_id_2" to mapOf(
                    FormatType.MSO_MDOC to listOf(
                        "credential2",
                    )
                ),
                "input_descriptor_id_3" to mapOf(
                    FormatType.VC_SD_JWT to listOf(
                        "credential3",
                    )
                ),
            ),
            holderId = "did:example:holder123",
            signatureSuite = "Ed25519Signature2018"
        )

// The wallet can now iterate through unsignedVPTokens and sign each one
val signingResults = unsignedVPTokens.map { unsignedVpToken ->
    val signature = signData(unsignedVpToken.dataToSign, unsignedVpToken.holderKeyReference, unsignedVpToken.signatureAlgorithm)
    VPTokenSigningResultV2(signedData = signature)
}

// Use the signing results with constructVPResponseV2
val response = openID4VP.constructVPResponseV2(signingResults)
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if:
    - Provided verifiable credentials list is empty
    - `holderId` is not provided for `LDP_VC` format (required to populate `holderKeyReference` in the response)
    - `signatureSuite` is not provided for `LDP_VC` format
    - No mapping found for a specific credential format
    - Invalid credential structure

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### constructVPResponse
- Constructs a `vp_token` with proof using the provided `VPTokenSigningResult` and `presentation_submission` which can be sent to the Verifier (Verifying party).
- Returns back a map of VP response as per the response mode.

**Note 1:** When sharing multiple MSO_MDOC credentials, the verifier is responsible for mapping each credential to its corresponding input descriptor. This mapping is not handled by the library since the ISO standard does not define such a mapping mechanism.


```kotlin
    val response : Map<String, Any> = openID4VP.constructVPResponse(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>)
```

#### Request Parameters

| Name                  | Type                                  | Description                                                                                                                                                   |
|-----------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | Map<FormatType, VPTokenSigningResult> | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |

### Response Parameters

Map<String, Any> contains the following properties:

1. If the response mode is related to unencrypted - `direct_post` or `iar-post`:
    - "vp_token": The constructed VP token.
    - "presentation_submission": The presentation submission as a Map<String, Any>.
2. If response mode is related to encrypted - `direct_post.jwt` or `iar-post.jwt`:
    - "response": The encrypted data of the VP response with payload of the JWT containing `vp_token` and `presentation_submission`.


#### Example usage

```kotlin
 val ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws = "ey....qweug",
    signatureAlgorithm = "RsaSignature2018",
    publicKey = publicKey,
    domain = "<domain>"
)
val mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication = mapOf(
        "<mdoc-docType>" to DeviceAuthentication(
            signature = "ey....qweug",
            algorithm = "ES256",
        )
    )
)
val sdJwtVPTokenSigningResult = SdJwtVPTokenSigningResult(
    uuidToKbJWTSignature = mapOf(
        "uuid" to "signature" // only signature part of the signed kb-jwt
    )
)
val vpTokenSigningResults : Map<FormatType, VPTokenSigningResult> = mapOf(
    FormatType.LDP_VC to ldpVPTokenSigningResult,
    FormatType.MSO_MDOC to mdocVPTokenSigningResult,
    FormatType.VC_SD_JWT to sdJwtVPTokenSigningResult,
    FormatType.DC_SD_JWT to sdJwtVPTokenSigningResult,
)
val response : Map<String,Any> = openID4VP.constructVPResponse(vpTokenSigningResults = vpTokenSigningResults)
```


#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InvalidData exception is thrown if the response_type in the authorization request is not supported

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.



### constructVPResponseV2
- Constructs a `vp_token` with proof using the provided list of `VPTokenSigningResultV2` (simplified signing results) and `presentation_submission` which can be sent to the Verifier (Verifying party).
- This is the V2 API that works with the flattened list of signed data from `constructUnsignedVPTokenV2`, simplifying the signing workflow by accepting a simple list of signatures in the same order as the unsigned tokens.
- Returns back a map of VP response as per the response mode.

**Note:** This method automatically reconstructs the format-specific signing results internally, so the wallet only needs to provide signatures in the same order as received from `constructUnsignedVPTokenV2`.

```kotlin
    val response : Map<String, Any> = openID4VP.constructVPResponseV2(vpTokenSigningResults: List<VPTokenSigningResultV2>)
```

#### Request Parameters

| Name                  | Type                         | Description                                                                                                                               |
|-----------------------|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | List<VPTokenSigningResultV2> | A list of signing results in the same order as the unsigned tokens from `constructUnsignedVPTokenV2`. Each contains only the signed data. |


#### Response Parameters

Map<String, Any> contains the following properties:

1. If the response mode is related to unencrypted - `direct_post` or `iar-post`:
    - "vp_token": The constructed VP token.
    - "presentation_submission": The presentation submission as a Map<String, Any>.
2. If response mode is related to encrypted - `direct_post.jwt` or `iar-post.jwt`:
    - "response": The encrypted data of the VP response with payload of the JWT containing `vp_token` and `presentation_submission`.


#### Example usage

```kotlin
// First, get unsigned tokens
val unsignedVPTokens : List<UnsignedVPTokenV2> = openID4VP.constructUnsignedVPTokenV2(
    verifiableCredentials = mapOf(
        "input_descriptor_id_1" to mapOf(
            FormatType.LDP_VC to listOf(<ldp-vc-json>)
        ),
        "input_descriptor_id_2" to mapOf(
            FormatType.MSO_MDOC to listOf("credential2")
        ),
        "input_descriptor_id_3" to mapOf(
            FormatType.VC_SD_JWT to listOf("credential3")
        )
    ),
    holderId = "did:example:holder123",
    signatureSuite = "Ed25519Signature2018"
)

// Sign each token and create signing results in the same order
val signingResults = unsignedVPTokens.map { token ->
    val signature = wallet.sign(
        data = token.dataToSign,
        keyReference = token.holderKeyReference,
        algorithm = token.signatureAlgorithm
    )
    VPTokenSigningResultV2(signedData = signature)
}

// Construct the VP response
val vpResponse : Map<String, Any> = openID4VP.constructVPResponseV2(
    vpTokenSigningResults = signingResults
)
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InvalidData exception is thrown if:
    - The response_type in the authorization request is not supported
    - The number of signing results doesn't match the expected number of unsigned tokens
    - Invalid signature data provided

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### sendVPResponseToVerifier
- Constructs a `vp_token` with proof using the provided `VPTokenSigningResult`, then sends it along with the `presentation_submission` to the Verifier via an HTTP POST request.
- Returns back the response received from the Verifier. Refer here for the structure of VerifierResponse - [VerifierResponse structure](#verifierresponse-structure)

**Note 1:** When sharing multiple MSO_MDOC credentials, the verifier is responsible for mapping each credential to its corresponding input descriptor. This mapping is not handled by the library since the ISO standard does not define such a mapping mechanism.


```kotlin
    val response : VerifierResponse = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>)
```

#### Request Parameters

| Name                  | Type                                  | Description                                                                                                                                                   |
|-----------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | Map<FormatType, VPTokenSigningResult> | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |

### Response Parameters

VerifierResponse contains the following properties:

#### VerifierResponse structure

| Name             | Type             | Description                                                                                                   |
|------------------|------------------|---------------------------------------------------------------------------------------------------------------|
| statusCode       | Int              | HTTP status code received from the Verifier                                                                   |
| redirectUri      | String           | The redirect URI to which the wallet application needs to redirect after sending the response to the Verifier |     
| additionalParams | Map<String, Any> | A map containing any additional response body parameters received from the Verifier                           |
| headers          | Map<String, Any> | A map containing any headers received from the Verifier                                                       |


#### Example usage

```kotlin
 val ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws = "ey....qweug",
    signatureAlgorithm = "RsaSignature2018",
    publicKey = publicKey,
    domain = "<domain>"
)
val mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication = mapOf(
        "<mdoc-docType>" to DeviceAuthentication(
            signature = "ey....qweug",
            algorithm = "ES256",
        )
    )
)
val sdJwtVPTokenSigningResult = SdJwtVPTokenSigningResult(
    uuidToKbJWTSignature = mapOf(
        "uuid" to "signature" // only signature part of the signed kb-jwt
    )
)
val vpTokenSigningResults : Map<FormatType, VPTokenSigningResult> = mapOf(
    FormatType.LDP_VC to ldpVPTokenSigningResult,
    FormatType.MSO_MDOC to mdocVPTokenSigningResult,
    FormatType.VC_SD_JWT to sdJwtVPTokenSigningResult,
    FormatType.DC_SD_JWT to sdJwtVPTokenSigningResult,
)
val response : VerifierResponse = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults = vpTokenSigningResults)
```


#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
4. InvalidData exception is thrown if the response_type in the authorization request is not supported

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### shareVerifiablePresentation (deprecated, use sendVPResponseToVerifier instead)
- Constructs a `vp_token` with proof using the provided `VPTokenSigningResult`, then sends it along with the `presentation_submission` to the Verifier via an HTTP POST request.
- Returns a response to the consumer app (e.g., mobile app) indicating whether the Verifiable Credentials were successfully shared with the Verifier.

**Note 1:** When sharing multiple MSO_MDOC credentials, the verifier is responsible for mapping each credential to its corresponding input descriptor. This mapping is not handled by the library since the ISO standard does not define such a mapping mechanism.


```kotlin
//NOTE: New API contract
    val response : String = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>) 

//NOTE: Old API contract for backward compatibility
    val response : String = openID4VP.shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata)
```

#### Request Parameters

| Name                  | Type                                  | Description                                                                                                                                                   |
|-----------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | Map<FormatType, VPTokenSigningResult> | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |


#### Example usage

```kotlin
 val ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws = "ey....qweug",
    signatureAlgorithm = "RsaSignature2018",
    publicKey = publicKey,
    domain = "<domain>"
)
val mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication = mapOf(
        "<mdoc-docType>" to DeviceAuthentication(
            signatue = "ey....qweug",
            algorithm = "ES256",
        )
    )
)
val sdJwtVPTokenSigningResult = SdJwtVPTokenSigningResult(
    uuidToKbJWTSignature = mapOf(
        "uuid" to "signature" // only signature part of the signed kb-jwt
    )
)
val vpTokenSigningResults : Map<FormatType, VPTokenSigningResult> = mapOf(
    FormatType.LDP_VC to ldpVPTokenSigningResult,
    FormatType.MSO_MDOC to mdocVPTokenSigningResult,
    FormatType.VC_SD_JWT to sdJwtVPTokenSigningResult,
    FormatType.DC_SD_JWT to sdJwtVPTokenSigningResult,
)
val response : String = openID4VP.shareVerifiablePresentation(vpTokenSigningResults = vpTokenSigningResults)
```


#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
4. InvalidData exception is thrown if the response_type in the authorization request is not supported

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### constructErrorInfo

- Receives an exception and constructs the Authorization Error response as per OpenID4VP specification.
- Returns back the constructed error response as a Map<String, Any>.

#### Request Parameters

| Name      | Type      | Description                                 |
|-----------|-----------|---------------------------------------------|
| exception | Exception | The Exception related to the error occurred |

#### Response Parameters

| Type             | Description                                                                                                                      |
|------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Map<String, Any> | This will be a map with error and error_description which is the Authorization Error response as per the OpenID4VP specification |

##### Example Response

```shell
{
  "error" : "access_Denied"
  "error_description" : "User did not give consent to share the requested Credentials with the Verifier.",
  "state" : "<state>"
}
```


#### Example usage

```kotlin
// Example: The user declines to share the requested credentials. In this case, Verifier needs to be informed about the scenario.
// So call the sendErrorInfoToVerifier method with appropriate exception message to notify the Verifier.

val verifierResponse: Map<String,Any> = openID4VP.constructErrorInfo(
    OpenID4VPExceptions.AccessDenied(
        message = "User did not give consent to share the requested Credentials with the Verifier.",
        className = this.className
    )
)
```
#### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.

 
### sendErrorInfoToVerifier

- Receives an exception and sends it's message to the Verifier via an HTTP POST request to the Verifier's response_uri endpoint.
- Returns back the response received from the Verifier. Refer here for the structure of VerifierResponse - [VerifierResponse structure](#verifierresponse-structure)

```kotlin
// Example: The user declines to share the requested credentials. In this case, Verifier needs to be informed about the scenario.
// So call the sendErrorInfoToVerifier method with appropriate exception message to notify the Verifier.

val verifierResponse: VerifierResponse = openID4VP.sendErrorInfoToVerifier(
    OpenID4VPExceptions.AccessDenied(
        message = "User did not give consent to share the requested Credentials with the Verifier.",
        className = this.className
    )
)
```
#### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.


### sendErrorToVerifier  (deprecated, use sendErrorInfoToVerifier instead)
- Receives an exception and sends it's message to the Verifier via an HTTP POST request.

```kotlin
 openID4VP.sendErrorToVerifier(exception: Exception)
```

#### Parameters

| Name      | Type      | Description                        |
|-----------|-----------|------------------------------------|
| exception | Exception | This contains the exception object |

#### Example usage

```kotlin
openID4VP.sendErrorToVerifier(Exception("User did not give consent to share the requested Credentials with the Verifier."))
```
#### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.

### Exception Handling Enhancement

- The library has been enhanced to handle exceptions more gracefully. Library is throwing `OpenID4VPExceptions` now which gives both Error Code, Message and optional state to the consumer app. The `state` value is extracted from the authorization request and is included in the error response only if it is present and non-empty. This allows the consumer app to handle exceptions more effectively and provide better user experience.
- For the backward compatibility, the library will still throw the exceptions with `message` which can be referred in sample application `io.mosip.sampleapp.utils.OpenID4VPManager`. However, it is recommended to use the new `OpenID4VPExceptions` for better error handling.

### OpenID4VPExceptions structure

OpenID4VPExceptions is a sealed class that encapsulates various exception types that can occur within the OpenID4VP library. Each exception type extends the base class and provides specific error handling for different scenarios.

This exception has the following properties:

1. errorCode: A unique code representing the type of error.
2. message: A descriptive message providing details about the error.
3. verifierResponse: An optional property that holds the Verifier response obtained while sending the error to Verifier. Refer here for the structure of VerifierResponse - [VerifierResponse structure](#verifierresponse-structure)
4. className: The name of the class where the exception occurred.


## 🚨 Deprecation Notice

The following methods are deprecated and will be removed in future releases. Please migrate to the suggested alternatives.

| Method Name                 | Description                                   | Deprecated Since | Suggested Alternative                                   |
|-----------------------------|-----------------------------------------------|------------------|---------------------------------------------------------|
| shareVerifiablePresentation | Sends VP (Authorization response) to verifier | 0.6.0            | [sendVPResponseToVerifier](#sendvpresponsetoverifier)   |
| sendErrorToVerifier         | Sends Authorization error to the verifier     | 0.6.0            | [sendErrorInfoToVerifier](#senderrorinfotoverifier)     |
