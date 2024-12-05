/*
    Implements BBS end points in a way paralleling the ECDSA-SD endpoints
*/
import express from 'express';
import { credentialValidator, proofValidator } from './validators.js';
import { derive } from './lib/BBSderive.js'
import { signBase } from './lib/BBSsignBase.js'
import { verifyBase } from './lib/BBSverifyBase.js'
import { verifyDerived } from './lib/BBSverifyDerived.js'
import { localLoader } from './documentLoader.js'
import { logger } from './logging.js'
import { isBBS_base, extractPublicKey, getServerKeyPairBBS } from './helpers.js';
import { API_ID_BBS_SHA, prepareGenerators } from './lib/BBS.js'

// Pre-compute BBS generators for up to 100 messages
const gens = await prepareGenerators(101, API_ID_BBS_SHA);

// Obtain key material and process into byte array format
const keyPair = await getServerKeyPairBBS();

export const bbsRouter = express.Router()

let issue_req_count = 0;
let verify_req_count = 0;
let verifyBase_req_count = 0;
let derive_req_count = 0;


// Used in BBS to add a **base proof** to an unsigned credential
// Endpoint: POST /credentials/issue, object:{credential, mandatoryPointers, options}.

bbsRouter.post('/credentials/issue', async function (req, res, next) {
    logger.info(`Issue request #${++issue_req_count}`, {api: "BBSissue", body: req.body, reqNum: issue_req_count});
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
        let mandatoryPointers = req.body.options?.mandatoryPointers;
        if (!mandatoryPointers) {
            mandatoryPointers = [];
        }
        const signCred = await signBase(document, keyPair, mandatoryPointers, localOptions, gens);
        logger.info(`Response to issue request #${issue_req_count}`, {api: "BBSissue", doc: signCred, reqNum: issue_req_count});
        res.status(201).json(signCred);
    } catch (error) {
        error.api = 'BBSissue';
        error.reqNum = issue_req_count;
        return next(error);
    }
})

// Used to verify a BBS derived credential
// Endpoint: POST /credentials/verify, object: {verifiableCredential, options}

bbsRouter.post('/credentials/verify', async function (req, res, next) {
    logger.info(`BBS Verify request #${++verify_req_count}`,
      {api: "BBSverify", body: req.body, reqNum: verify_req_count});
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
        const proofValue = signedDoc.proof?.proofValue;
        let pubKey = extractPublicKey(signedDoc);
        if (isBBS_base(proofValue)) {
            logger.info(`Responding to verify request #${verify_req_count} Not a Derived Proof verified`,
              {api: "BBSverify", reqNum: verify_req_count});
            res.status(400).json({ checks: [], warnings: [] });
            return;
        } else { // This is a derived proof
            const result = await verifyDerived(signedDoc, pubKey, localOptions, gens);
            logger.info(`Responding to verify request #${verify_req_count} Derived Proof verified: ${result}`,
              {api: "BBSverify", reqNum: verify_req_count});
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        }
    } catch (err) {
        err.api = 'BBSverify';
        err.reqNum = verify_req_count;
        err.type = "invalidProof";
        // console.log(err);
        return next(err);
    }
})

// Used to verify a BBS  credential with a signed base proof
// Endpoint: POST /credentials/verifyBase, object: {verifiableCredential, options}

bbsRouter.post('/credentials/verifyBase', async function (req, res, next) {
    logger.info(`Verify request #${++verifyBase_req_count}`,
      {api: "BBSverifyBase", body: req.body, reqNum: verifyBase_req_count});
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
        proofValidator(signedDoc.proof);
        const proofValue = signedDoc.proof?.proofValue;
        let pubKey = extractPublicKey(signedDoc);
        if (isBBS_base(proofValue)) {
            const result = await verifyBase(signedDoc, pubKey, localOptions, gens);
            logger.info(`Responding to verify request #${verifyBase_req_count} Base Proof verified: ${result}`,
              {api: "BBSverifyBase", reqNum: verifyBase_req_count});
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        } else { // This is a derived proof
            logger.info(`Responding to BBS verifyBase request #${verifyBase_req_count} Not a Base Proof`,
              {api: "BBSverifyBase", reqNum: verifyBase_req_count});
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        }
    } catch (err) {
        err.api = 'BBSverifyBase';
        err.reqNum = verifyBase_req_count;
        return next(err);
    }
})

// Used to issue a selectively disclosed BBS credential with derived proof
// POST /credentials/derive, object: {verifiableCredential, selectivePointers, options}.
bbsRouter.post('/credentials/derive', async function (req, res, next) {
    logger.info(`Derived request #${++derive_req_count}`, {api: "BBSderive", body: req.body, reqNum: derive_req_count});
    try {
        let document = req.body.verifiableCredential;
        let selectivePointers = req.body.options?.selectivePointers;
        let localOptions = req.body.options;
        if (!document) {
            throw { type: "missingDocument" };
        }
        credentialValidator(document);
        if (!selectivePointers) {
            throw { type: "nothingSelected"};
        }
        if (!document.proof) {
            throw { type: "missingProof" };
        }
        proofValidator(document.proof);
        localOptions = {};
        localOptions.documentLoader = localLoader;
        const derivedCred = await derive(document, selectivePointers, localOptions, gens)
        logger.info(`Response to derive request #${derive_req_count}`, {api: "BBSderive", doc: derivedCred, reqNum: derive_req_count});
        res.status(201).json(derivedCred);
        return
    } catch (error) {
        let err = error;
        if (!error.type) { // an exception from my BBS-VC library, rather than one I locally threw
            // Format it for easy handling
            err = {type: "deriveError", message: `${error}`}
        }
        err.api = 'BBSderive';
        err.reqNum = derive_req_count;
        return next(err);
    }
});
