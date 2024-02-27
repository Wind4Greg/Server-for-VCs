import { concatBytes } from '@noble/hashes/utils' // bytesToHex lives here too
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { p256 } from '@noble/curves/p256'
import { createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from './primitives.js'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

/**
 * verify a signed selective disclosure derived document (credential) with ECDSA-SD
 * procedures. This is done by a verifier on receipt of the credential.
 *
 * @param {Object} document - The signed SD derived credential
 * @param {Uint8Array} pubKey - Byte array for the issuers P256 public key without multikey prefixes
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function verifyDerived (doc, pubKey, options) {
  const document = klona(doc)
  const proof = document.proof
  const proofValue = proof.proofValue
  const proofConfig = klona(document.proof)
  delete proofConfig.proofValue
  proofConfig['@context'] = document['@context']
  delete document.proof // **IMPORTANT** from now on we work with the document without proof!!!!!!!
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })
  const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8
  // console.log(`Proof hash: ${bytesToHex(proofHash)}`)
  // Parse Derived ProofValue
  if (!proofValue.startsWith('u')) {
    throw new Error('proofValue not a valid multibase-64-url encoding')
  }
  const decodedProofValue = base64url.decode(proofValue)
  // check header bytes are: 0xd9, 0x5d, and 0x01
  if (decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d || decodedProofValue[2] !== 0x01) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(decodedProofValue.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  let [baseSignature, publicKey, signatures, labelMapCompressed, mandatoryIndexes] = decodeThing
  if (!baseSignature.BYTES_PER_ELEMENT === 1 && baseSignature.length === 64) {
    throw new Error('Bad baseSignature in proofValue')
  }
  publicKey = new Uint8Array(publicKey) // Just to make sure convert into byte array
  if (!Array.isArray(signatures)) {
    throw new Error('signatures in proof value is not an array')
  }
  signatures.forEach(function (value) {
    if (!value.BYTES_PER_ELEMENT === 1 && value.length === 64) {
      throw new Error('Bad signature in signatures array in proofValue')
    }
  })
  // cbor library workaround for issue https://github.com/hildjj/node-cbor/issues/186
  if (!(labelMapCompressed instanceof Map) && (Object.keys(labelMapCompressed).length === 0)) {
    labelMapCompressed = new Map()
  }
  if (!(labelMapCompressed instanceof Map)) {
    throw new Error('Bad label map in proofValue')
  }
  labelMapCompressed.forEach(function (value, key) {
    if (!Number.isInteger(key) || value.length !== 32) {
      throw new Error('Bad key or value in compress label map in proofValue')
    }
  })
  if (!Array.isArray(mandatoryIndexes)) {
    throw new Error('mandatory indexes is not an array in proofValue')
  }
  mandatoryIndexes.forEach(value => {
    if (!Number.isInteger(value)) {
      throw new Error('Value in mandatory indexes  is not an integer')
    }
  })
  // Decompress the Label Map
  const labelMap = new Map()
  labelMapCompressed.forEach(function (v, k) {
    const key = 'c14n' + k
    const value = base64url.encode(v)
    labelMap.set(key, value)
  })
  // console.log(labelMap)
  const labelMapFactoryFunction = await createLabelMapFunction(labelMap)
  const nquads = await labelReplacementCanonicalizeJsonLd(document, labelMapFactoryFunction,
    options)
  // Separate mandatory from non-mandatory nquads
  const mandatory = []
  const nonMandatory = []
  nquads.forEach(function (value, index) {
    if (mandatoryIndexes.includes(index)) {
      mandatory.push(value)
    } else {
      nonMandatory.push(value)
    }
  })
  const mandatoryHash = sha256(mandatory.join(''))
  // console.log(`mandatory hash: ${bytesToHex(mandatoryHash)}`)
  // console.log(mandatory)
  if (signatures.length !== nonMandatory.length) {
    throw new Error('signature and nonMandatory counts do not match')
  }
  const toVerify = concatBytes(proofHash, publicKey, mandatoryHash)
  // Verify base signature
  const msgHash = sha256(toVerify) // Hash is done outside of the algorithm in noble/curve case.
  let verificationResult = p256.verify(baseSignature, msgHash, pubKey)
  // console.log(`baseSignature verified: ${verificationResult}`)
  const ephemeralPubKey = publicKey.slice(2)
  nonMandatory.forEach(function (quad, index) {
    const msgHash = sha256(quad) // Hash is done outside of the algorithm in noble/curve case.
    const sigVerified = p256.verify(signatures[index], msgHash, ephemeralPubKey)
    // console.log(`sig ${index} verified: ${sigVerified}`)
    verificationResult &&= sigVerified
  })
  return verificationResult
}
