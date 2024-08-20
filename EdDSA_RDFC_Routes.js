/*
    Implements EdDSA-RDFC end points (P-256 curve)
*/
import express from 'express';
import { credentialValidator, proofValidator } from './validators.js';
import { eddsa_rdfc_sign, eddsa_rdfc_verify } from './lib/EdDSA_RDFC_signVerify.js';
import { logger } from './logging.js'
import { extractPublicKey, getServerKeyPair } from './helpers.js';
import { localLoader } from './documentLoader.js'

// Obtain key material and process into byte array format
const keyPair = await getServerKeyPair('EdDSAKeyMaterial.json');

export const eddsa_rdfcRouter = express.Router()

let issue_req_count = 0;
let verify_req_count = 0;

// Used in ECDA-RDFC to add a **proof** to an unsigned credential
// Endpoint: POST /credentials/issue, object:{credential, options}.

eddsa_rdfcRouter.post('/credentials/issue', async function (req, res, next) {
    logger.info(`Issue request #${++issue_req_count}`, {api: "EdDSA_RDFCissue", body: req.body, reqNum: issue_req_count});
    try {
        let document = req.body.credential;
        if (!document) {
            throw { type: "missingDocument" };
        }
        credentialValidator(document);
        const localOptions = {};
        localOptions.documentLoader = localLoader;
        // Check if we need context inject of data integrity per
        // https://w3c.github.io/vc-data-integrity/#context-injection
        if (!document["@context"].includes("https://www.w3.org/ns/credentials/v2")) {
            // add data integrity to context if not there
            if (!document["@context"].includes("https://w3id.org/security/data-integrity/v2")) {
                document["@context"].push("https://w3id.org/security/data-integrity/v2");
            }
        }
        const signCred = await eddsa_rdfc_sign(document, keyPair, localOptions);
        console.log(JSON.stringify(signCred, null, 2));
        logger.info(`Response to issue request #${issue_req_count}`, {api: "EdDSA_RDFCissue", doc: signCred, reqNum: issue_req_count});
        res.status(201).json(signCred);
    } catch (error) {
        error.api = 'EdDSA_RDFCissue';
        error.reqNum = issue_req_count;
        return next(error);
    }
})

// Used to verify a EdDSA-RDFC credential
// Endpoint: POST /credentials/verify, object: {verifiableCredential, options}

eddsa_rdfcRouter.post('/credentials/verify', async function (req, res, next) {
    logger.info(`EdDSA-RDFC Verify request #${++verify_req_count}`,
      {api: "EdDSA_RDFCverify", body: req.body, reqNum: verify_req_count});
    const signedDoc = req.body.verifiableCredential;
    try {
        if (!signedDoc) {
            throw { type: "missingDocument" };
        }
        credentialValidator(signedDoc);
        const localOptions = {};
        localOptions.documentLoader = localLoader;
        if (!signedDoc.proof) {
            throw { type: "missingProof" };
        }
        proofValidator(signedDoc.proof, req.body.options);
        // Check crypto suite
        if (signedDoc.proof.cryptosuite !== "eddsa-rdfc-2022")  {
            throw { type: "cryptosuiteMismatch" };
        }
        const proofValue = signedDoc.proof?.proofValue;
        let pubKey = extractPublicKey(signedDoc);
        const result = await eddsa_rdfc_verify(signedDoc, pubKey, localOptions);
        logger.info(`Responding to verify request #${verify_req_count} Proof verified: ${result}`,
              {api: "EdDSA_RDFCverify", reqNum: verify_req_count});
        let statusCode = 200;
        if (!result) {
            statusCode = 400;
        }
        res.status(statusCode).json({ checks: [], warnings: [] });
        return;
    } catch (err) {
        err.api = 'EdDSA_RDFCverify';
        err.reqNum = verify_req_count;
        err.type = "invalidProof";
        // console.log(err);
        return next(err);
    }
})

