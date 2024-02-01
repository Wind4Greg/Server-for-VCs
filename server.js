import express from 'express';
import { credentialValidator, proofValidator } from './validators.js';
import { derive } from './lib/derive.js'
import { signBase } from './lib/signBase.js'
import { verifyBase } from './lib/verifyBase.js'
import { verifyDerived } from './lib/verifyDerived.js'
import { localLoader } from './documentLoader.js'
import { isECDSA_SD_base, extractPublicKey, getServerKeyPair } from './helpers.js';


// JSON input protection
let jsonParser = express.json({ limit: 10000 }); // 10KB

// Obtain key material and process into byte array format
const keyPair = await getServerKeyPair();

const app = express();
let issue_req_count = 0;
let verify_req_count = 0;
let derive_req_count = 0;


// Used in ECDSA-SD to add a **base proof** to an unsigned credential
// Endpoint: POST /credentials/issue, object:{credential, mandatoryPointers, options}.

app.post('/credentials/issue', jsonParser, async function (req, res, next) {
    console.log(`Received issue request #${++issue_req_count}`);
    // Take a look at what we are receiving
    console.log(JSON.stringify(req.body, null, 2));
    try {
        let document = req.body.credential;
        if (!document) {
            throw { type: "missingDocument" };
        }
        credentialValidator(document);
        let options = req.body.options;

        if (!options) {
            options = {};
        }
        options.documentLoader = localLoader;
        // Check if we need context inject of data integrity per
        // https://w3c.github.io/vc-data-integrity/#context-injection
        if (!document["@context"].includes("https://www.w3.org/ns/credentials/v2")) {
            // add data integrity to context if not there
            if (!document["@context"].includes("https://w3id.org/security/data-integrity/v2")) {
                document["@context"].push("https://w3id.org/security/data-integrity/v2");
            }
        }
        let mandatoryPointers = req.body.mandatoryPointers;
        if (!mandatoryPointers) {
            mandatoryPointers = [];
        }
        const signCred = await signBase(document, keyPair, mandatoryPointers, options);
        console.log(`Responding to issue request #${issue_req_count} with signed document:`);
        console.log(JSON.stringify(signCred, null, 2));
        res.status(201).json(signCred);
    } catch (error) {
        return next(error);
    }
})

// Used to verify a derived credential, or a credential with a signed base proof
// Endpoint: POST /credentials/verify, object: {verifiableCredential, options}

app.post('/credentials/verify', jsonParser, async function (req, res, next) {
    console.log(`Received verify request #${++verify_req_count}`);
    // Take a look at what we are receiving
    console.log(JSON.stringify(req.body, null, 2));
    const signedDoc = req.body.verifiableCredential;
    try {
        if (!signedDoc) {
            throw { type: "missingDocument" };
        }
        credentialValidator(signedDoc);
        const options = req.body.options;
        options.documentLoader = localLoader;
        if (!signedDoc.proof) {
            throw { type: "missingProof" };
        }
        proofValidator(signedDoc.proof);
        const proofValue = signedDoc.proof?.proofValue;
        let pubKey = extractPublicKey(signedDoc);
        if (isECDSA_SD_base(proofValue)) {
            const result = await verifyBase(signedDoc, pubKey, options);
            console.log(`Responding to verify request #${verify_req_count} Base Proof verified: ${result}`);
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        } else { // This is a derived proof
            const result = await verifyDerived(signedDoc, pubKey, options);
            console.log(`Responding to verify request #${verify_req_count} Derived Proof verified: ${result}`);
            let statusCode = 200;
            if (!result) {
                statusCode = 400;
            }
            res.status(statusCode).json({ checks: [], warnings: [] });
            return;
        }
    } catch (err) {
        return next(err);
    }
})

// Used to issue a selectively disclosed credential with derived proof
// POST /credentials/derive, object: {verifiableCredential, selectivePointers, options}.
app.post('/credentials/derive', jsonParser, async function (req, res, next) {
    console.log(`Received derived request #${++derive_req_count}`);
    // Take a look at what we are receiving
    console.log(JSON.stringify(req.body, null, 2));
    try {
        let document = req.body.verifiableCredential;
        let selectivePointers = req.body.selectivePointers;
        let options = req.body.options;
        if (!document) {
            throw { type: "missingDocument" };
        }
        credentialValidator(document);
        if (!selectivePointers) {
            throw { type: "nothingSelected"};
        }
        if (!options) {
            options = {};
        }
        if (!document.proof) {
            throw { type: "missingProof" };
        }
        proofValidator(document.proof);
        options.documentLoader = localLoader;
        const derivedCred = await derive(document, selectivePointers, options)
        console.log(`Responding to derive request #${derive_req_count} with derived document:`);
        console.log(JSON.stringify(derivedCred, null, 2));
        res.status(201).json(derivedCred);
        return
    } catch (error) {
        console.log(`Error deriving: ${error}`);
        let err = error;
        if (!error.type) { // an exception from my ECDSA-SD library, rather than one I locally threw
            // Format it for easy handling
            err = {type: "deriveError", message: `${error}`}
        }
        return next(err);
    }
});

// Error handling here
app.use((err, req, res, next) => {
    console.log("Error handler received a call with error:");
    console.error(err);
    let errorType = err.type;
    if (!errorType) {
        res.status(500).json({ error: err });
        return;
    }
    errorType = errorType.trim();
    console.log(`errorType: ${errorType}`);
    switch (errorType) {
        case "entity.too.large":
            res.status(400).json({ errors: [`JSON input limit of ${err.limit} exceeded`] });
            return;
        case "invalidCredential":
            res.status(400).json({ errors: [err.errors[0].message] });
            return;
        case "invalidProof":
            res.status(400).json({ errors: ["proof: " + err.errors[0].message] });
            return;
        case "missingDocument":
            res.status(400).json({ errors: ["no credential supplied"] });
            return;
        case "missingProof":
            res.status(400).json({ errors: ["no proof on credential"] });
            return;
        case "nothingSelected":
            res.status(400).json({ errors: ["Nothing selected"]});
            return;
        case "deriveError":
            res.status(400).json({errors: [err.message]});
            return;
        default:
            res.status(500).json({ errors: ["Unknown"] });
            return;
    }
})


const host = '127.0.0.2'; // Servers local IP address.
const port = '5555';
app.listen(port, host, function () {
    console.log(`Example app listening on IPv4: ${host}:${port}`);
});

