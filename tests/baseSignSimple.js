import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
const urlBase = "http://localhost:5150/";

const testDataPath = './fixture-data/'
const document = JSON.parse(
    await readFile(new URL(testDataPath + 'windDoc.json', import.meta.url)));
const mandatoryPointers = JSON.parse(
        await readFile(new URL(testDataPath + 'windMandatory.json', import.meta.url)));

describe("Simple Base Signing", function () {
    it("With document and mandatory pointers", async function () {
        const content = {credential: document, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });

});
