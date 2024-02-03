import Ajv from "ajv"
import addFormats from "ajv-formats"
import { readFile } from 'fs/promises'

const ajv = new Ajv({allowUnionTypes: true}) // options can be passed, e.g. {allErrors: true}
addFormats(ajv);

// Credential checking
const credSchema = JSON.parse(
    await readFile(new URL('./credValidSchema.json', import.meta.url)));
const credSchema11 = JSON.parse(
    await readFile(new URL('./credV11Restrictions.json', import.meta.url)));
const credSchema2 = JSON.parse(
    await readFile(new URL('./credV2Restrictions.json', import.meta.url)));

const credValidate = ajv.compile(credSchema);
const credV11restrictions = ajv.compile(credSchema11);
const credV2restrictions = ajv.compile(credSchema2);

export function credentialValidator(cred) {
    let valid = credValidate(cred)
    if (!valid) {
        throw {type: "invalidCredential",
                errors: credValidate.errors};
    }
    // check if v1.1 credential and validate
    if (cred["@context"].includes('https://www.w3.org/2018/credentials/v1')) {
        valid = credV11restrictions(cred)
        if (!valid) {
            throw {type: "invalidCredential",
            errors: credV11restrictions.errors};
        }
    }
    if (cred["@context"].includes('https://www.w3.org/ns/credentials/v2')) {
        valid = credV2restrictions(cred)
        if (!valid) {
            throw {type: "invalidCredential",
            errors: credV2restrictions.errors};
        }
    }


}

// Proof checking
const proofSchema = JSON.parse(
    await readFile(new URL('./proofValidSchema.json', import.meta.url)));

const proofValidate = ajv.compile(proofSchema);

export function proofValidator(cred) {
    const valid = proofValidate(cred)
    if (!valid) {
        throw {type: "invalidProof",
                errors: proofValidate.errors};
    }
}