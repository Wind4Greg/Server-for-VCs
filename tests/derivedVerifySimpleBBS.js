import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/'
const fileName = 'derivedDocumentBBS.json'; // This file uses an empty presentation header.
// const fileName = 'tempDerived.json';
const signedDerived = JSON.parse(
    await readFile(new URL(testDataPath + fileName, import.meta.url)));

describe("BBS: Simple Derived Verify", function () {
    it("With signed derived document", async function () {
        const content = {verifiableCredential: signedDerived, options: {}};
        let res = await fetch(urlBase + "BBS/credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isOk(res.ok);
    });

});
