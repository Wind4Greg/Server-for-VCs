import express from 'express';
import { credentialValidator, proofValidator } from './validators.js';
import { derive } from './lib/derive.js'
import { errorHandler } from './errorHandler.js';
import { signBase } from './lib/signBase.js'
import { verifyBase } from './lib/verifyBase.js'
import { verifyDerived } from './lib/verifyDerived.js'
import { localLoader } from './documentLoader.js'
import { logger } from './logging.js'
import { isECDSA_SD_base, extractPublicKey, getServerKeyPair } from './helpers.js';
import { bbsRouter } from './BBSroutes.js';


// JSON input protection
let jsonParser = express.json({ limit: 10000 }); // 10KB

// Obtain key material and process into byte array format
const keyPair = await getServerKeyPair();

const app = express();
let issue_req_count = 0;
let verify_req_count = 0;
let verifyBase_req_count = 0;
let derive_req_count = 0;

app.use(jsonParser);

// Used in ECDSA-SD to add a **base proof** to an unsigned credential
// Endpoint: POST /credentials/issue, object:{credential, mandatoryPointers, options}.

app.post('/credentials/issue', async function (req, res, next) {
    logger.info(`Issue request #${++issue_req_count}`, {api: "issue", body: req.body, reqNum: issue_req_count});
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
        const signCred = await signBase(document, keyPair, mandatoryPointers, localOptions);
        logger.info(`Response to issue request #${issue_req_count}`, {api: "issue", doc: signCred, reqNum: issue_req_count});
        res.status(201).json(signCred);
    } catch (error) {
        error.api = 'issue';
        error.reqNum = issue_req_count;
        return next(error);
    }
})

// Used to verify a derived credential
// Endpoint: POST /credentials/verify, object: {verifiableCredential, options}

app.post('/credentials/verify', async function (req, res, next) {
    logger.info(`Verify request #${++verify_req_count}`, {api: "verify", body: req.body, reqNum: verify_req_count});
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
        if (isECDSA_SD_base(proofValue)) {
            logger.info(`Responding to verify request #${verify_req_count} Not a Derived Proof`, {api: "verify", reqNum: verify_req_count});
            res.status(400).json({ checks: [], warnings: [] });
            return;
        } else { // This is a derived proof
            const result = await verifyDerived(signedDoc, pubKey, localOptions);
            logger.info(`Responding to verify request #${verify_req_count} Derived Proof verified: ${result}`, {api: "verify", reqNum: verify_req_count});
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        }
    } catch (error) {
        let err = error;
        if (!error.type) { // an exception from my ECDSA-SD library, rather than one I locally threw
            // Format it for easy handling
            err = {type: "verifyError", message: `${error}`}
        }
        err.api = 'verify';
        err.reqNum = verify_req_count;
        return next(err);
    }
})

// Used to verify a credential with a signed base proof
// Endpoint: POST /credentials/verifyBase, object: {verifiableCredential, options}

app.post('/credentials/verifyBase', async function (req, res, next) {
    logger.info(`VerifyBase request #${++verifyBase_req_count}`,
      {api: "verifyBase", body: req.body, reqNum: verifyBase_req_count});
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
        if (isECDSA_SD_base(proofValue)) {
            const result = await verifyBase(signedDoc, pubKey, localOptions);
            logger.info(`Responding to verifyBase request #${verifyBase_req_count} Base Proof verified: ${result}`,
              {api: "verifyBase", reqNum: verifyBase_req_count});
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        } else { // This is a derived proof
            logger.info(`Responding to verifyBase request #${verifyBase_req_count} Not a Base Proof`,
              {api: "verifyBase", reqNum: verifyBase_req_count});
            res.status(400).json({ checks: [], warnings: [] });
            return;
        }
    } catch (error) {
        let err = error;
        if (!error.type) { // an exception from my ECDSA-SD library, rather than one I locally threw
            // Format it for easy handling
            err = {type: "verifyBaseError", message: `${error}`}
        }
        err.api = 'verifyBase';
        err.reqNum = verifyBase_req_count;
        return next(err);
    }
})

// Used to issue a selectively disclosed credential with derived proof
// POST /credentials/derive, object: {verifiableCredential, selectivePointers, options}.
app.post('/credentials/derive', async function (req, res, next) {
    logger.info(`Derived request #${++derive_req_count}`, {api: "derive", body: req.body, reqNum: derive_req_count});
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
        const derivedCred = await derive(document, selectivePointers, localOptions)
        logger.info(`Response to derive request #${derive_req_count}`, {api: "derive", doc: derivedCred, reqNum: derive_req_count});
        res.status(201).json(derivedCred);
        return
    } catch (error) {
        let err = error;
        if (!error.type) { // an exception from my ECDSA-SD library, rather than one I locally threw
            // Format it for easy handling
            err = {type: "deriveError", message: `${error}`}
        }
        err.api = 'derive';
        err.reqNum = derive_req_count;
        return next(err);
    }
});

// Add BBS end points
app.use('/BBS', bbsRouter);

// Error handling here
app.use(errorHandler);

const host = 'localhost'; // Servers local IP address.
const port = '5150';
app.listen(port, host, function () {
    logger.info(`Example app listening on IPv4: ${host}:${port}`);
});

