import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
const urlBase = "http://127.0.0.2:5555/";

const testDataPath = './fixture-data/'
const signedDerived = JSON.parse(
    await readFile(new URL(testDataPath + 'derivedRevealDocument.json', import.meta.url)));

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
