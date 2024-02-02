import { assert } from "chai";
import fetch from "node-fetch";
import { klona } from "klona";
import { readFile } from 'fs/promises'
import { urlBase } from './testConfig.js'

const testDataPath = './fixture-data/'
const document = JSON.parse(
    await readFile(new URL(testDataPath + 'windDoc.json', import.meta.url)));
const mandatoryPointers = JSON.parse(
        await readFile(new URL(testDataPath + 'windMandatory.json', import.meta.url)));


describe("Bad Signing Inputs", function () {
    it("JSON too big", async function () {
        const modDoc = klona(document);
        let tooLong = "";
        for (let i = 0; i < 10000; i++) {
            tooLong += "Winds Up!";
        }
        modDoc.credentialSubject.nickName = tooLong;
        const content = {credential: modDoc, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isNotOk(res.ok);
    });
    it("Missing @context", async function () {
        const modDoc = klona(document);
        delete modDoc["@context"];
        const content = {credential: modDoc, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isNotOk(res.ok);
    });
    it("Missing type property", async function () {
        const modDoc = klona(document);
        delete modDoc["type"];
        const content = {credential: modDoc, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isNotOk(res.ok);
    });
    it("Missing credentialSubject property", async function () {
        const modDoc = klona(document);
        delete modDoc["credentialSubject"];
        const content = {credential: modDoc, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isNotOk(res.ok);
    });
    it("Missing issuer property", async function () {
        const modDoc = klona(document);
        delete modDoc["issuer"];
        const content = {credential: modDoc, options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isNotOk(res.ok);
    });
    it("Missing document", async function () {
        const content = {options: {mandatoryPointers}};
        let res = await fetch(urlBase + "credentials/issue", {
        method: "POST",
        body: JSON.stringify(content),
        headers: {
            "Content-Type": "application/json",
        },
        });
        console.log(`return code: ${res.status}`);
        console.log(JSON.stringify(await res.json()));
        assert.isNotOk(res.ok);
    });
});
