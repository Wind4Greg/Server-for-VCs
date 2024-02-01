import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
const urlBase = "http://127.0.0.2:5555/";

const testDataPath = './fixture-data/'
const signedBase = JSON.parse(
    await readFile(new URL(testDataPath + 'addSignedSDBase.json', import.meta.url)));
const selectivePointers = JSON.parse(
        await readFile(new URL(testDataPath + 'windSelective.json', import.meta.url)));

describe("Simple Deriving", function () {
    it("With signed base and selective pointers", async function () {
        const content = {verifiableCredential: signedBase, options: {selectivePointers}};
        let res = await fetch(urlBase + "credentials/derive", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(JSON.stringify(await res.json()));
        assert.isOk(res.ok);
    });

});
