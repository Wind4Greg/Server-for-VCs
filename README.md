---
title: Server for Simple VC-API
author: Dr. Greg M. Bernstein
date: 2024-01-22
---

# Server for Signing and Verifying VCs

In order to interoperability test my implementations of ECDSA-SD and BBS I need a server that can respond to a very limited subset of VC-API requests. This is the start of such a minimal server built with Express.js. Included in the `lib` directory are functions for implementing ECDSA-SD. I've also set up a local (JSON-LD) context loader in `documentLoader.js` the various supported contexts are in the directory `contexts`.

For information on my ECDSA-SD implementation see the complete documentation with example code at [ECDSA-SD-Library](https://github.com/Wind4Greg/ECDSA-SD-Library).

# Notes on additional testing for ECDSA-SD

Unlike `ecdsa-rdfc-2019` and `ecdsa-jcs-2019`, `ecdsa-sd-2023` has three (or four) rather than two fundamental functions to be tested. These are roughly

* **Add Base**: inputs: unsigned document, mandatory pointers. returns a signed base document. Can use the [VC-API: issue credential](https://w3c-ccg.github.io/vc-api/#issue-credential) API but need to supplement the `options` object to support `mandatoryPointers` or have it as a separate item. Endpoint: POST /credentials/issue, object:{credential, mandatoryPointers, options}.
* **Verify Base**: *technically not required in the specification, but needed to know if someones base proof meets the spec*. inputs:s signed base document. In my ECDSA-SD library I provide a high level function for this. Could use the [VC-API: verify credential](https://w3c-ccg.github.io/vc-api/#verify-credential) API to check this. Endpoint: POST /credentials/verify, object: {verifiableCredential, options}
* **Derive Proof**: inputs: signed base document, selective pointers; Returns signed derived document. Can use the [VC-API derive credential](https://w3c-ccg.github.io/vc-api/#derive-credential) API, however the `frame` field is out of date and should be replace by a `selectivePointers` field of type array. Endpoint: POST /credentials/derive, object: {verifiableCredential, selectivePointers, options}.
* **Verify Derived**: input: signed derived document, Returns true or false; Should use the [VC-API: verify credential](https://w3c-ccg.github.io/vc-api/#verify-credential) API to check this.

## Proof Value Checking

For both base proof and derived proof the encoding is *base64url-no-pad-encoding* and **not** *base-58-btc* and starts with a `u` and **not** a 'z'. In addition the decoded proofs should start with the following bytes:

* **base proof** header bytes 0xd9, 0x5d, and 0x00
* **disclosure proof** header bytes 0xd9, 0x5d, and 0x01

# Notes

These are just my rough notes for now...

## Requirements

From the interop test suite instructions:

> You will need an issuer and verifier that are compatible with VC API and are capable of handling issuance and verification of Verifiable Credentials with DataIntegrityProof proof type using the ecdsa-rdfc-2019, ecdsa-jcs-2019, or ecdsa-sd-2023 cryptosuites.

Issuance: [VC-API Issue Credential](https://w3c-ccg.github.io/vc-api/#issue-credential),

Method and endpoint: POST /credentials/issue

Takes as inputs: unsigned credential, and options.

Verification: [VC-API Verify Credential](https://w3c-ccg.github.io/vc-api/#verify-credential)

Method and endpoint: POST /credentials/verify

Takes as inputs: signed credential, and options

Since I'm just implementing ECDSA-SD here I will restrict to those using Data Integrity.

From the data integrity specification:

2.1 Proofs

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

Refined in the ECDSA specification:

2.2.1 DataIntegrityProof

The verificationMethod property of the proof MUST be a URL. Dereferencing the verificationMethod MUST result in an object containing a type property with the value set to Multikey.

The type property of the proof MUST be DataIntegrityProof.

The cryptosuite property of the proof MUST be ecdsa-rdfc-2019 or ecdsa-jcs-2019.

The created property of the proof MUST be an [XMLSCHEMA11-2] formatted date string.

The proofPurpose property of the proof MUST be a string, and MUST match the verification relationship expressed by the verification method controller.

The value of the proofValue property of the proof MUST be an ECDSA signature produced according to [FIPS-186-5] and SHOULD use the deterministic ECDSA signature variant, produced according to [FIPS-186-5] using the curves and hashes as specified in section 3. Algorithms, encoded according to section 7 of [RFC4754] (sometimes referred to as the IEEE P1363 format), and encoded using the base-58-btc header and alphabet as described in the Multibase section of [VC-DATA-INTEGRITY].