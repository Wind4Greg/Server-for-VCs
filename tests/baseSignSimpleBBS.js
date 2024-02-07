import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/'
const fileName = 'windDoc.json'; // "interopIssue.json"; //
const document = JSON.parse(
    await readFile(new URL(testDataPath + fileName, import.meta.url)));
const mandatoryPointers = JSON.parse(
        await readFile(new URL(testDataPath + 'windMandatory.json', import.meta.url)));
// const mandatoryPointers = [];
describe("Simple Base Signing", function () {
    it("With document and mandatory pointers", async function () {
        const content = {credential: document, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "BBS/credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        assert.isOk(res.ok);
    });

});
