import { concatBytes } from '@noble/hashes/utils' // bytesToHex is in here too
import { base58btc } from 'multiformats/bases/base58'
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { ed25519 as ed } from '@noble/curves/ed25519';
import { extractPublicKey } from '../helpers.js';

const PRE_MKEY_ED25519 = new Uint8Array([0xed, 0x01]);
/**
 * sign a document (credential) with EdDSA-RDFC procedures.
 *
 * @param {Object} document - The unsigned credential
 * @param {Object} keyPair - The issuers private/public key pair
 * @param {Uint8Array} keyPair.priv - Byte array for the P256 private key without multikey prefixes
 * @param {Uint8Array} keyPair.pub - Byte array for the P256 public key without multikey prefixes
 * @param {Object} options - A variety of options to control signing and processing
 * @param {Object} options.proofConfig - proof configuration options without `@context`
 *  field. Optional. This will be generated with current date information and
 *  did:key verification method otherwise.
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function eddsa_rdfc_sign(document, keyPair, options) {
  // Set up proof configuration and canonize
  let proofConfig = {}
  if (options.proofConfig !== undefined) {
    proofConfig = Object.assign({}, options.proofConfig)
  } else { // Create the proofConfig
    proofConfig.type = 'DataIntegrityProof'
    proofConfig.cryptosuite = 'eddsa-rdfc-2022'
    const nd = new Date()
    proofConfig.created = nd.toISOString()
    const publicKeyMultibase = base58btc.encode(concatBytes(PRE_MKEY_ED25519, keyPair.pub))
    proofConfig.verificationMethod = 'did:key:' + publicKeyMultibase + '#' + publicKeyMultibase
    proofConfig.proofPurpose = 'assertionMethod'
  }
  proofConfig['@context'] = document['@context']
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })
  const proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
  delete proofConfig['@context']; // don't include this in  proof
  // Canonize the document
  const cannon = await jsonld.canonize(document, { documentLoader: options.documentLoader })
  const docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
  // Combine hashes
  const combinedHash = concatBytes(proofHash, docHash);
  // Sign
  let signature = ed.sign(combinedHash, keyPair.priv);


  // Construct Signed Document
  let signedDocument = Object.assign({}, document);
  signedDocument.proof = proofConfig;
  signedDocument.proof.proofValue = base58btc.encode(signature);
  return signedDocument;
}
// **TODO** update this for proof sets and chains...
/**
 * verify a signed document (credential) with EdDSA-RDFC
 * procedures. This is done by a verifier on receipt of the credential.
 *
 * @param {Object} document - The signed SD derived credential
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function eddsa_rdfc_verify(signedDocument, options) {
  // Document without proof
  let document = Object.assign({}, signedDocument);
  delete document.proof;
  let proofs = signedDocument.proof;
  if (!Array.isArray(proofs)) { // If not an array make it a one element array
    proofs = [proofs];
  }

  // Need to iterate over all proofs and check validity
  for (let proof of proofs) {
    // Check crypto suite
    if (proof.cryptosuite !== "eddsa-rdfc-2022") {
      throw { type: "cryptosuiteMismatch" };
    }
    // Get matching, depending
    if (proof.previousProof) {
      let matchingProofs = findMatchingProofs(proof.previousProof, proofs);
      document.proof = matchingProofs; // This is the "temporary" chained doc
    }
    // Canonize the "chained" document
    let cannon = await jsonld.canonize(document);
    delete document.proof; // Remove it after canonization
    // Hash canonized document
    let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8

    // Set proof options
    let proofConfig = Object.assign({}, proof);
    delete proofConfig.proofValue;
    proofConfig["@context"] = signedDocument["@context"];

    // canonize the proof config
    let proofCanon = await jsonld.canonize(proofConfig);
    // Hash canonized proof config
    let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
    // Combine hashes
    let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft
    // Get public key
    let pbk = extractPublicKey({proof: proof});
    // Verify
    let signature = base58btc.decode(proof.proofValue);
    let result = await ed.verify(signature, combinedHash, pbk);
    if (!result) {
      return result;
    }
  }
  return true;
}

// function to get all matching proofs (only first level no dependencies)
// prevProofs is either a string or an array
// proofs is an array of proofs
function findMatchingProofs(prevProofs, proofs) {
  let matches = [];
  if (Array.isArray(prevProofs)) {
    prevProofs.forEach(pp => {
      let matchProof = proofs.find(p => p.id === pp);
      if (!matchProof) {
        throw new Error(`Missing proof for id = ${pp}`);
      }
      matches.push(matchProof);
    })
  } else {
    let matchProof = proofs.find(p => p.id === prevProofs);
    if (!matchProof) {
      throw new Error(`Missing proof for id = ${prevProofs}`);
    }
    matches.push(matchProof);
  }
  return matches;
}