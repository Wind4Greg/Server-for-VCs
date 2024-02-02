import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
const urlBase = "http://localhost:5150/";

const testDataPath = './fixture-data/';
const fileName = 'addSignedSDBase.json';
// const fileName = 'dbSigned1.json';
const signedBase = JSON.parse(
    await readFile(new URL(testDataPath + fileName, import.meta.url)));

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
