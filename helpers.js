// Helper functions
import { hexToBytes } from '@noble/hashes/utils';
import { readFile } from 'fs/promises';
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'

export function isECDSA_SD_base(proofValue) {
    const proofValueBytes = base64url.decode(proofValue)
    // console.log(proofValueBytes.length);
    // check header bytes are: 0xd9, 0x5d, and 0x00
    if (proofValueBytes[0] == 0xd9 && proofValueBytes[1] == 0x5d && proofValueBytes[2] == 0x00) {
        return true;
    } else {
        return false;
    }
}

export function isBBS_base(proofValue) {
    const proofValueBytes = base64url.decode(proofValue)
    // console.log(proofValueBytes.length);
    // check header bytes are: 0xd9, 0x5d, and 0x02
    if (proofValueBytes[0] == 0xd9 && proofValueBytes[1] == 0x5d && proofValueBytes[2] == 0x02) {
        return true;
    } else {
        return false;
    }
}

export function extractPublicKey(signedDoc) {
    const verificationMethod = signedDoc.proof?.verificationMethod;
    if (!verificationMethod.startsWith('did:key:')) {
        throw new TypeError('Only can handle did:key verification at this time');
    }
    const encodedPbk = verificationMethod.split('did:key:')[1].split('#')[0]
    let pbk = base58btc.decode(encodedPbk)
    pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
    // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
    return pbk;
}

export async function getServerKeyPair() {
    // Obtain key material and process into byte array format
    const keyMaterial = JSON.parse(
        await readFile(new URL('./SDKeyMaterial.json', import.meta.url)))
    // Sample long term issuer signing key
    const keyPair = {}
    keyPair.priv = base58btc.decode(keyMaterial.privateKeyMultibase).slice(2)
    keyPair.pub = base58btc.decode(keyMaterial.publicKeyMultibase).slice(2)
    return keyPair;
}

export async function getServerKeyPairBBS() {
    // Obtain key material and process into byte array format
    const keyMaterial = JSON.parse(
        await readFile(new URL('./BBSKeyMaterial.json', import.meta.url)))
    // Sample long term issuer signing key
    const keyPair = {}
    keyPair.priv = hexToBytes(keyMaterial.privateKeyHex)
    keyPair.pub = hexToBytes(keyMaterial.publicKeyHex)
    return keyPair;
}