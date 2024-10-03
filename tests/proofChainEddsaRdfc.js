import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/'
let fileNameSigned = 'signedProofChainSimple1.json';
const signedDocSimple1 = JSON.parse(
        await readFile(new URL(testDataPath + fileNameSigned, import.meta.url)));
fileNameSigned = 'signedProofSet.json';
const signedDocSet = JSON.parse(
                await readFile(new URL(testDataPath + fileNameSigned, import.meta.url)));
fileNameSigned = 'signedProofChainSimple2.json';
const signedDocSimpleChain = JSON.parse(
                await readFile(new URL(testDataPath + fileNameSigned, import.meta.url)));
fileNameSigned = 'signedProofChain2.json';
const signedDocExtendedChain = JSON.parse(
                await readFile(new URL(testDataPath + fileNameSigned, import.meta.url)));

describe("Proof Set and Chain EdDSA-RDFC Verification", function () {
    this.timeout(0); // Turn off timeouts
    it("Simple ECDA-RDFC Verification", async function () {
        const content = {verifiableCredential: signedDocSimple1, options: {}};
        let res = await fetch(urlBase + "EdDSA-RDFC/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });
    it("Proof Set ECDA-RDFC Verification", async function () {
        const content = {verifiableCredential: signedDocSet, options: {}};
        let res = await fetch(urlBase + "EdDSA-RDFC/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });
    it("Proof Chain Simple ECDA-RDFC Verification", async function () {
        const content = {verifiableCredential: signedDocSimpleChain, options: {}};
        let res = await fetch(urlBase + "EdDSA-RDFC/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });
    it("Proof Chain Extended ECDA-RDFC Verification", async function () {
        const content = {verifiableCredential: signedDocExtendedChain, options: {}};
        let res = await fetch(urlBase + "EdDSA-RDFC/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });
});
