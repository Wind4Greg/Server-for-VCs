import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
const urlBase = "http://127.0.0.2:5555/";

const testDataPath = './fixture-data/'
const signedBase = JSON.parse(
    await readFile(new URL(testDataPath + 'addSignedSDBase.json', import.meta.url)));

describe("Simple Base Verify", function () {
    it("With signed base document", async function () {
        const content = {verifiableCredential: signedBase, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });

});
