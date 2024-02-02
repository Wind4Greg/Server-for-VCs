import { assert } from "chai";
import fetch from "node-fetch";
import { klona } from "klona";
import { readFile } from 'fs/promises'
const urlBase = "http://localhost:5150/";

const testDataPath = './fixture-data/'
const document = JSON.parse(
    await readFile(new URL(testDataPath + 'addSignedSDBase.json', import.meta.url)));


describe("Bad Verify Inputs", function () {
    it("JSON too big", async function () {
        const modDoc = klona(document);
        let tooLong = "";
        for (let i = 0; i < 10000; i++) {
            tooLong += "Winds Up!";
        }
        modDoc.credentialSubject.nickName = tooLong;
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
        const content = {options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
    it("Missing proof property", async function () {
        const modDoc = klona(document);
        delete modDoc["proof"];
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
    it("Missing proof.type property", async function () {
        const modDoc = klona(document);
        delete modDoc.proof.type;
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
    it("Missing proof.proofPurpose property", async function () {
        const modDoc = klona(document);
        delete modDoc.proof.proofPurpose;
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
    it("Missing proof.verificationMethod property", async function () {
        const modDoc = klona(document);
        delete modDoc.proof.verificationMethod;
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
    it("Missing proof.proofValue property", async function () {
        const modDoc = klona(document);
        delete modDoc.proof.proofValue;
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
    it("Missing proof.cryptosuite property", async function () {
        const modDoc = klona(document);
        delete modDoc.proof.cryptosuite;
        const content = {verifiableCredential: modDoc, options: {}};
        let res = await fetch(urlBase + "credentials/verify", {
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
