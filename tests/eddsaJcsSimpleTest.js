import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/'
const fileName = 'unsigned.json';
const document = JSON.parse(
    await readFile(new URL(testDataPath + fileName, import.meta.url)));
const fileNameSigned = 'signedEdDSA_JCS.json';
const signedDoc = JSON.parse(
        await readFile(new URL(testDataPath + fileNameSigned, import.meta.url)));

describe("Simple EdDSA-JCS Sign and Verify", function () {
    it("EdDSA-JCS Signing", async function () {
        const content = {credential: document, options: {}};
        let res = await fetch(urlBase + "EdDSA-JCS/credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });
    it("ECDA-JCS Verification", async function () {
        const content = {verifiableCredential: signedDoc, options: {}};
        let res = await fetch(urlBase + "EdDSA-JCS/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });
});
