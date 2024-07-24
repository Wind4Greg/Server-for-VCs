/*
    Implements ECDSA-JCS end points.
*/
import express from 'express';
import { credentialValidator, proofValidator } from './validators.js';
import { ecdsa_jcs_sign, ecdsa_jcs_verify } from './lib/ECDSA_JCS_signVerify.js';
import { logger } from './logging.js'
import { extractPublicKey, getServerKeyPair } from './helpers.js';

// Obtain key material and process into byte array format
const keyPair = await getServerKeyPair(); // ECDSA P256

export const ecdsa_jcsRouter = express.Router()

let issue_req_count = 0;
let verify_req_count = 0;

// Used in ECDA-JCS to add a **proof** to an unsigned credential
// Endpoint: POST /credentials/issue, object:{credential, options}.

ecdsa_jcsRouter.post('/credentials/issue', async function (req, res, next) {
    logger.info(`Issue request #${++issue_req_count}`, {api: "ECDSA_JCSissue", body: req.body, reqNum: issue_req_count});
    try {
        let document = req.body.credential;
        if (!document) {
            throw { type: "missingDocument" };
        }
        credentialValidator(document);
        const localOptions = {};
        // Do we need to do context injection in JCS case?
        // Check if we need context inject of data integrity per
        // https://w3c.github.io/vc-data-integrity/#context-injection
        if (!document["@context"].includes("https://www.w3.org/ns/credentials/v2")) {
            // add data integrity to context if not there
            if (!document["@context"].includes("https://w3id.org/security/data-integrity/v2")) {
                document["@context"].push("https://w3id.org/security/data-integrity/v2");
            }
        }
        const signCred = ecdsa_jcs_sign(document, keyPair, localOptions);
        logger.info(`Response to issue request #${issue_req_count}`, {api: "ECDSA_JCSissue", doc: signCred, reqNum: issue_req_count});
        res.status(201).json(signCred);
    } catch (error) {
        error.api = 'ECDSA_JCSissue';
        error.reqNum = issue_req_count;
        return next(error);
    }
})

// Used to verify a ECDSA-JCS credential
// Endpoint: POST /credentials/verify, object: {verifiableCredential, options}

ecdsa_jcsRouter.post('/credentials/verify', async function (req, res, next) {
    logger.info(`ECDSA-JCS Verify request #${++verify_req_count}`,
      {api: "ECDSA_JCSverify", body: req.body, reqNum: verify_req_count});
    const signedDoc = req.body.verifiableCredential;
    try {
        if (!signedDoc) {
            throw { type: "missingDocument" };
        }
        credentialValidator(signedDoc);
        const localOptions = {};
        if (!signedDoc.proof) {
            throw { type: "missingProof" };
        }
        proofValidator(signedDoc.proof, req.body.options);
        const proofValue = signedDoc.proof?.proofValue;
        let pubKey = extractPublicKey(signedDoc);
        const result = await ecdsa_jcs_verify(signedDoc, pubKey, localOptions);
        logger.info(`Responding to verify request #${verify_req_count} Derived Proof verified: ${result}`,
              {api: "ECDSA_JCSverify", reqNum: verify_req_count});
        let statusCode = 200;
        if (!result) {
            statusCode = 400;
        }
        res.status(statusCode).json({ checks: [], warnings: [] });
        return;
    } catch (err) {
        err.api = 'ECDSA_JCSverify';
        err.reqNum = verify_req_count;
        err.type = "invalidProof";
        // console.log(err);
        return next(err);
    }
})

