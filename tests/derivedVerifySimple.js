import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
const urlBase = "http://localhost:5150/";

const testDataPath = './fixture-data/'
const fileName = 'derivedRevealDocument.json';
// const fileName = 'dbSigned2.json';
const signedDerived = JSON.parse(
    await readFile(new URL(testDataPath + fileName, import.meta.url)));

describe("Simple Derived Verify", function () {
    it("With signed derived document", async function () {
        const content = {verifiableCredential: signedDerived, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
