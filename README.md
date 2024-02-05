---
title: Server for Simple VC-API
author: Dr. Greg M. Bernstein
date: 2024-01-22
---

# Server for Signing and Verifying VCs

In order to interoperability test my implementations of ECDSA-SD and BBS I need a server that can respond to a very limited subset of VC-API requests. This is the start of such a minimal server built with Express.js. Included in the `lib` directory are functions for implementing ECDSA-SD. I've also set up a local (JSON-LD) context loader in `documentLoader.js` the various supported contexts are in the directory `contexts`.

For information on my ECDSA-SD implementation see the complete documentation with example code at [ECDSA-SD-Library](https://github.com/Wind4Greg/ECDSA-SD-Library).

## Implementation Notes

References and techniques:

* [Express.js Error Handling](https://expressjs.com/en/guide/error-handling.html) Explains working with exceptions and in particular how to write the error handler. When dealing with async function see the reference below.
* [Using async/await in Express](https://zellwk.com/blog/async-await-express/). I'm currently using Express.js 4.x. This article explains a bit about dealing with exceptions and async functions. I use a lot of exceptions to try and keep the control flow clean and this article shows a straightforward way to do this when using async functions.

As a testing/reference server I needed to have good logging capabilities so trying to use common tools and techniques. Here are the references I consulted:

* [express logging advice](https://expressjs.com/en/advanced/best-practice-performance.html#for-app-activity)
* [Comparing node.js logging tools](https://blog.logrocket.com/comparing-node-js-logging-tools/)
* [Winston](https://github.com/winstonjs/winston#readme) Using this.
* [Logform](https://github.com/winstonjs/logform?tab=readme-ov-file#json) More on winston log formats. I'm just combining "timestamp" with the JSON format.
* [Winston daily rotate file](https://www.npmjs.com/package/winston-daily-rotate-file) will look into this once I get deployment working a bit.
* [Winston Tutorial](https://stackify.com/winston-logging-tutorial/) Looks reasonable.
* [How To Use Winston to Log Node.js Applications on Ubuntu 20.04](https://www.digitalocean.com/community/tutorials/how-to-use-winston-to-log-node-js-applications-on-ubuntu-20-04#step-2-customizing-the-logging-variables) Shows combining *morgan* for HTTP request logging with *winston* for logging everything else. I've not implemented something like this yet.

# Notes on additional testing for ECDSA-SD

Unlike `ecdsa-rdfc-2019` and `ecdsa-jcs-2019`, `ecdsa-sd-2023` has three (or four) rather than two fundamental functions to be tested. These are:

* **Add Base**: inputs: unsigned document, mandatory pointers. returns a signed base document. Using the [VC-API: issue credential](https://w3c-ccg.github.io/vc-api/#issue-credential) API with the addition of `mandatoryPointers` as a subfield of the *options* property. Endpoint: POST /credentials/issue, object:{credential, options}. **Note**: current implementation does not implement any options besides `mandatoryPointers`.
* **Verify Base**: *technically not required in the specification, but needed to know if someones base proof meets the spec*. inputs: signed base document. In my ECDSA-SD library I provide a high level function for this. Using the [VC-API: verify credential](https://w3c-ccg.github.io/vc-api/#verify-credential) API to check this. Endpoint: POST /credentials/verify, object: {verifiableCredential, options}. **Note**: current implementation does not implement any options.
* **Derive Proof**: inputs: signed base document, selective pointers; Returns signed derived document. Using the [VC-API derive credential](https://w3c-ccg.github.io/vc-api/#derive-credential) API, however the `frame` field is out of date and is removed, in addition a `selectivePointers` field of type array is added as a subfield of the existing *options* property. Endpoint: POST /credentials/derive, object: {verifiableCredential, options}. **Note**: current implementation does not implement any options besides `selectivePointers`.
* **Verify Derived**: input: signed derived document, Returns true or false; Using the [VC-API: verify credential](https://w3c-ccg.github.io/vc-api/#verify-credential) API to check this. Endpoint: POST /credentials/verify, object: {verifiableCredential, options}. **Note**: current implementation does not implement any options.

Note: The *verify base* and *verify derived* use the same POST `/credential/verify` endpoint. The server looks at the `proofValue` information to determine which verification function to call.

## Credential Basic Validation

When asked to sign a credential should perform some basic sanity checks on the contents of the credential. We can get these from the VC data models.

JSON schema references:

* [JSON Schema](https://json-schema.org/)
* [Working with Multiple Types](https://cswr.github.io/JsonSchema/spec/multiple_types/), shows how to deal with properties that could have multiple types such as either a `string` or an `array`.
* [Generic Keywords](https://cswr.github.io/JsonSchema/spec/generic_keywords/), includes the useful `anyOf` keyword/construct.
* [Schema Valdator](https://www.jsonschemavalidator.net/) a nice site to interactively test schemas and data.

### VC Data Model 1.1

See Section 4 of [Verifiable Credential Data Model v1.1](https://www.w3.org/TR/vc-data-model/#basic-concepts).

* Verifiable credentials and verifiable presentations **MUST** include a `@context` property.
* This specification defines the **optional** `id` property for such identifiers. If present the value of the id property **MUST** be a URI.
* Verifiable credentials and verifiable presentations **MUST** have a `type` property.
* A verifiable credential **MUST** have a `credentialSubject` property.
* A verifiable credential **MUST** have an `issuer` property.
* A credential **MUST** have an `issuanceDate` property. The value of the issuanceDate property MUST be a string value of an [XMLSCHEMA11-2] combined date-time string representing the date and time the credential becomes valid, which could be a date and time in the future.
* When embedding a proof, the `proof` property **MUST** be used.
* If present, the value of the `expirationDate` property **MUST** be a string value of an [XMLSCHEMA11-2] date-time representing the date and time the credential ceases to be valid.
* If present, the value of the `credentialStatus` property

### VC Data Model 2.0

From Section 4 of [Verifiable Credential Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/#basic-concepts)

* Verifiable credentials and verifiable presentations MUST include a @context property.
* This specification defines the optional `id` property for such identifiers. The value of the `id` property **MUST** be a URL which MAY be dereferenced.
* Verifiable credentials and verifiable presentations MUST have a `type` property.
* `name` An **OPTIONAL** property that expresses the name of the credential.
* `description` An **OPTIONAL** property that conveys specific details about a credential.
* A verifiable credential **MUST** have a `credentialSubject` property.
* A verifiable credential **MUST** have an `issuer` property.
* `validFrom` If present, the value of the validFrom property **MUST** be an [XMLSCHEMA11-2] dateTimeStamp string value representing the date and time the credential becomes valid
* `validUntil` If present, the value of the validUntil property **MUST** be an [XMLSCHEMA11-2] dateTimeStamp string value representing the date and time the credential ceases to be valid
* This specification defines the `credentialStatus` property for the discovery of information about the status of a verifiable credential, such as whether it is suspended or revoked.

## Proof Basic Validation

For both base proof and derived proof the encoding is *base64url-no-pad-encoding* and **not** *base-58-btc* and starts with a `u` and **not** a 'z'. In addition the decoded proofs should start with the following bytes:

* **base proof** header bytes 0xd9, 0x5d, and 0x00
* **disclosure proof** header bytes 0xd9, 0x5d, and 0x01

From the data integrity specification:

### 2.1 Proofs

```
id
    An optional identifier for the proof, which MUST be a URL [URL], such as a UUID as a URN (urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5). The usage of this property is further explained in Section 2.1.2 Proof Chains.
type
    The specific proof type used for the cryptographic proof MUST be specified as a string that maps to a URL [URL]. Examples of proof types include DataIntegrityProof and Ed25519Signature2020. Proof types determine what other fields are required to secure and verify the proof.
proofPurpose
    The reason the proof was created MUST be specified as a string that maps to a URL [URL]. The proof purpose acts as a safeguard to prevent the proof from being misused by being applied to a purpose other than the one that was intended. For example, without this value the creator of a proof could be tricked into using cryptographic material typically used to create a Verifiable Credential (assertionMethod) during a login process (authentication) which would then result in the creation of a Verifiable Credential they never meant to create instead of the intended action, which was to merely logging into a website.
verificationMethod
    The means and information needed to verify the proof MUST be specified as a string that maps to a [URL]. An example of a verification method is a link to a public key which includes cryptographic material that is used by a verifier during the verification process.
created
    The date and time the proof was created is OPTIONAL and, if included, MUST be specified as an [XMLSCHEMA11-2] dateTimeStamp string.
expires
    The expires property is OPTIONAL. If present, it MUST be an [XMLSCHEMA11-2] dateTimeStamp string specifying when the proof expires.
domain
    The domain property is OPTIONAL. It conveys one or more security domains in which the proof is meant to be used. If specified, the associated value MUST be either a string, or an unordered set of strings. A verifier SHOULD use the value to ensure that the proof was intended to be used in the security domain in which the verifier is operating. The specification of the domain parameter is useful in challenge-response protocols where the verifier is operating from within a security domain known to the creator of the proof. Example domain values include: domain.example (DNS domain), https://domain.example:8443 (Web origin), mycorp-intranet (bespoke text string), and b31d37d4-dd59-47d3-9dd8-c973da43b63a (UUID).
challenge
    A string value that SHOULD be included in a proof if a domain is specified. The value is used once for a particular domain and window of time. This value is used to mitigate replay attacks. Examples of a challenge value include: 1235abcd6789, 79d34551-ae81-44ae-823b-6dadbab9ebd4, and ruby.
proofValue
    A string value that contains the base-encoded binary data necessary to verify the digital proof using the verificationMethod specified. The contents of the value MUST be expressed with a header and encoding as described in Section 2.4 Multibase. The contents of this value are determined by a specific cryptosuite and set to the proof value generated by the Add Proof Algorithm for that cryptosuite. Alternative properties with different encodings specified by the cryptosuite MAY be used, instead of this property, to encode the data necessary to verify the digital proof.
previousProof
    An OPTIONAL string value or unordered list of string values. Each value identifies another data integrity proof that MUST verify before the current proof is processed. If an unordered list, all referenced proofs in the array MUST verify. This property is used in Section 2.1.2 Proof Chains.
nonce
    An OPTIONAL string value supplied by the proof creator. One use of this field is to increase privacy by decreasing linkability that is the result of deterministically generated signatures.
```

### Refined in the ECDSA specification:

2.2.1 DataIntegrityProof

```
The verificationMethod property of the proof MUST be a URL. Dereferencing the verificationMethod MUST result in an object containing a type property with the value set to Multikey.

The type property of the proof MUST be DataIntegrityProof.

The cryptosuite property of the proof MUST be ecdsa-rdfc-2019 or ecdsa-jcs-2019.

The created property of the proof MUST be an [XMLSCHEMA11-2] formatted date string.

The proofPurpose property of the proof MUST be a string, and MUST match the verification relationship expressed by the verification method controller.
```