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


app.post('/credentials/issue', express.json(), async function(req, res) {
    console.log(`Received issue request #${issue_req_count++}`);
    console.log(JSON.stringify(req.body, null, 2));
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

    // TODO: Check received information
    // TODO: if good prepare to sign
    let mandatoryPointers = [];
    //  async function signBase (document, keyPair, mandatoryPointers, options)
    const signCred = await signBase(document, keyPair, mandatoryPointers, options);
    res.status(201).json(signCred);
})

app.post('/credentials/verify', express.json(), function(req, res) {
    console.log(`Received verify request #${verify_req_count++}`);
    console.log(JSON.stringify(req.body, null, 2));
    res.json({note: "Not implemented yet"});
})

const host = '127.0.0.2'; // Servers local IP address.
const port = '5555';
app.listen(port, host, function () {
console.log(`Example app listening on IPv4: ${host}:${port}`);
});