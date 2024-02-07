import { assert } from "chai";
import fetch from "node-fetch";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/'
const signedBase = JSON.parse(
    await readFile(new URL(testDataPath + 'addSignedSDBaseBBS.json', import.meta.url)));
const selectivePointers = JSON.parse(
        await readFile(new URL(testDataPath + 'windSelective.json', import.meta.url)));

describe("Simple Deriving BBS", function () {
    it("With signed base and selective pointers", async function () {
        const content = {verifiableCredential: signedBase, options: {selectivePointers}};
        let res = await fetch(urlBase + "BBS/credentials/derive", {
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
