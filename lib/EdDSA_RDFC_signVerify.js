import { concatBytes } from '@noble/hashes/utils' // bytesToHex is in here too
import { base58btc } from 'multiformats/bases/base58'
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { ed25519 as ed } from '@noble/curves/ed25519';

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

/**
 * verify a signed selective disclosure derived document (credential) with EdDSA-RDFC
 * procedures. This is done by a verifier on receipt of the credential.
 *
 * @param {Object} document - The signed SD derived credential
 * @param {Uint8Array} pubKey - Byte array for the issuers P256 public key without multikey prefixes
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function eddsa_rdfc_verify(signedDocument, pubKey, options) {
  // Document without proof
  let document = Object.assign({}, signedDocument);
  delete document.proof;
  // Set proof options per draft
  let proofConfig = Object.assign({}, signedDocument.proof);
  delete proofConfig.proofValue;
  // Canonize the document
  const cannon = await jsonld.canonize(document, { documentLoader: options.documentLoader })
  // Hash canonized document
  const docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
  // canonize the proof config
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader });
  let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
  let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft
  // Verify
  const signature = base58btc.decode(signedDocument.proof.proofValue);
  const result = ed.verify(signature, combinedHash, pubKey);
  return result;
}
