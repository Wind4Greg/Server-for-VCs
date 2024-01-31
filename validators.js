import Ajv from "ajv"
import addFormats from "ajv-formats"
import { klona } from "klona";
import { readFile } from 'fs/promises'

const ajv = new Ajv({allowUnionTypes: true}) // options can be passed, e.g. {allErrors: true}
addFormats(ajv);

// Credential checking
const credSchema = JSON.parse(
    await readFile(new URL('./credValidSchema.json', import.meta.url)));

const credValidate = ajv.compile(credSchema);

export function credentialValidator(cred) {
    const valid = credValidate(cred)
    if (!valid) {
        let errorMsg = credValidate.errors[0].message;
        console.log(errorMsg);
        throw {type: "invalidCredential",
                errors: credValidate.errors};
    }
}

// Proof checking
const proofSchema = JSON.parse(
    await readFile(new URL('./proofValidSchema.json', import.meta.url)));

const proofValidate = ajv.compile(proofSchema);

export function proofValidator(cred) {
    const valid = proofValidate(cred)
    if (!valid) {
        let errorMsg = proofValidate.errors[0].message;
        console.log(errorMsg);
        throw {type: "invalidProof",
                errors: proofValidate.errors};
    }
}