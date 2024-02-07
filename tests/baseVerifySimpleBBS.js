import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/';
const fileName = 'addSignedSDBaseBBS.json';
// const fileName = 'dbSigned1.json';
const signedBase = JSON.parse(
    await readFile(new URL(testDataPath + fileName, import.meta.url)));

describe("Simple Base Verify", function () {
    it("With signed base document", async function () {
        const content = {verifiableCredential: signedBase, options: {}};
        let res = await fetch(urlBase + "BBS/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });

});
