---
title: Server for Simple VC-API
author: Dr. Greg M. Bernstein
date: 2024-01-22
---

# Server for Signing and Verifying VCs

In order to interoperability test my implementations of ECDSA-SD and BBS I need a server that can respond to a very limited subset of VC-API requests.

## Requirements

From the interop test suite instructions:

> You will need an issuer and verifier that are compatible with VC API and are capable of handling issuance and verification of Verifiable Credentials with DataIntegrityProof proof type using the ecdsa-rdfc-2019, ecdsa-jcs-2019, or ecdsa-sd-2023 cryptosuites.

Issuance: [VC-API Issue Credential](https://w3c-ccg.github.io/vc-api/#issue-credential),

Method and endpoint: POST /credentials/issue

Takes as inputs: unsigned credential, and options.

Verification: [VC-API Verify Credential](https://w3c-ccg.github.io/vc-api/#verify-credential)

Method and endpoint: POST /credentials/verify

Takes as inputs: signed credential, and options