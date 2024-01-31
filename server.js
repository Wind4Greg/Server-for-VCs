import express from 'express';
import { readFile } from 'fs/promises'
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'
import { credentialValidator, proofValidator } from './validators.js';
import { derive } from './lib/derive.js'
import { signBase } from './lib/signBase.js'
import { verifyBase } from './lib/verifyBase.js'
import { verifyDerived } from './lib/verifyDerived.js'
import { localLoader } from './documentLoader.js'


// JSON input protection
let jsonParser = express.json({ limit: 10000 }); // 10KB

// Obtain key material and process into byte array format
const keyMaterial = JSON.parse(
    await readFile(new URL('./SDKeyMaterial.json', import.meta.url)))
// Sample long term issuer signing key
const keyPair = {}
keyPair.priv = base58btc.decode(keyMaterial.privateKeyMultibase).slice(2)
keyPair.pub = base58btc.decode(keyMaterial.publicKeyMultibase).slice(2)
const app = express(`Server Public Key: ${keyMaterial.publicKeyMultibase}`);
let issue_req_count = 0;
let verify_req_count = 0;
let derive_req_count = 0;

console.log(`Server Public Key ${keyMaterial.publicKeyMultibase}`);


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
app.post('/credentials/derive', jsonParser, async function (req, res) {
    console.log(`Received derived request #${++derive_req_count}`);
    // Take a look at what we are receiving
    console.log(JSON.stringify(req.body, null, 2));
    // TODO: Check received information!!!!
    let document = req.body.verifiableCredential;
    let selectivePointers = req.body.selectivePointers;
    let options = req.body.options;
    if (!document) {
        res.status(400).json({ note: "error of some kind" });
        return;
    }
    if (!selectivePointers) {
        res.status(400).json({ errors: ["Nothing selected"], checks: [], warnings: [] });
    }
    if (!options) {
        options = {};
    }
    options.documentLoader = localLoader;

    //  async function signBase (document, keyPair, mandatoryPointers, options)
    try {
        const derivedCred = await derive(document, selectivePointers, options)
        console.log(`Responding to derive request #${derive_req_count} with derived document:`);
        console.log(JSON.stringify(derivedCred, null, 2));
        res.status(201).json(derivedCred);
        return
    } catch (error) {
        console.log(`Error deriving: ${error}`);
        res.status(400).json({ errors: [error], checks: [], warnings: [] });
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

// Helper functions

function isECDSA_SD_base(proofValue) {
    const proofValueBytes = base64url.decode(proofValue)
    // console.log(proofValueBytes.length);
    // check header bytes are: 0xd9, 0x5d, and 0x00
    if (proofValueBytes[0] == 0xd9 && proofValueBytes[1] == 0x5d && proofValueBytes[2] == 0x00) {
        return true;
    } else {
        return false;
    }
}

function extractPublicKey(signedDoc) {
    const verificationMethod = signedDoc.proof?.verificationMethod;
    if (!verificationMethod.startsWith('did:key:')) {
        throw new TypeError('Only can handle did:key verification at this time');
    }
    const encodedPbk = verificationMethod.split('did:key:')[1].split('#')[0]
    let pbk = base58btc.decode(encodedPbk)
    pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
    // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
    return pbk;
}