import express from 'express';
import { readFile } from 'fs/promises'
import { base58btc } from 'multiformats/bases/base58'
import {signBase} from './lib/signBase.js'
import { localLoader } from './documentLoader.js'

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
console.log(`Server Public Key ${keyMaterial.publicKeyMultibase}`);

// TODO: put limits on size in express.json

app.post('/credentials/issue', express.json(), async function(req, res) {
    console.log(`Received issue request #${issue_req_count++}`);
    // Take a look at what we are receiving
    console.log(JSON.stringify(req.body, null, 2));
    // TODO: Check received information
    let document = req.body.credential;
    let options = req.body.options;
    if (!document) {
        res.status(400).json({note: "error of some kind"});
        return;
    }
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
    // console.log(document);
    // TODO: if good prepare to sign
    let mandatoryPointers = [];
    //  async function signBase (document, keyPair, mandatoryPointers, options)
    const signCred = await signBase(document, keyPair, mandatoryPointers, options);
    console.log(`Responding to issue request #${issue_req_count++} with signed document:`);
    console.log(JSON.stringify(signCred, null, 2));
    res.status(201).json(signCred);
})

app.post('/credentials/verify', express.json(), function(req, res) {
    console.log(`Received verify request #${verify_req_count++}`);
    // Take a look at what we are receiving
    console.log(JSON.stringify(req.body, null, 2));
    const document = req.body;
    // Will need context injection stuff at some point.
    // if (!document["@context"].includes("https://www.w3.org/ns/credentials/v2")) {
    //     // add data integrity to context if not there
    //     if (!document["@context"].includes("https://w3id.org/security/data-integrity/v2")) {
    //         document["@context"].push("https://w3id.org/security/data-integrity/v2");
    //     }
    // }
    // async function verifyBase (doc, pubKey, options)
    res.status(400).json({errors: ["Not implemented yet"], checks: [], warnings: []});
})

const host = '127.0.0.2'; // Servers local IP address.
const port = '5555';
app.listen(port, host, function () {
console.log(`Example app listening on IPv4: ${host}:${port}`);
});