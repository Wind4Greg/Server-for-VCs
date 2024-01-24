import { concatBytes } from '@noble/hashes/utils' // bytesToHex lives here too
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { p256 } from '@noble/curves/p256'
import { createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup } from
  './primitives.js'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

/**
 * verify a signed selective disclosure base document (credential) with ECDSA-SD
 * procedures. This is done by an holder on receipt of the credential.
 *
 * @param {Object} document - The signed SD base credential
 * @param {Uint8Array} pubKey - Byte array for the issuers P256 public key without multikey prefixes
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function verifyBase (doc, pubKey, options) {
  // parseBaseProofValue:
  const document = klona(doc)
  const proof = klona(document.proof)
  delete document.proof // IMPORTANT: all work uses document without proof
  const proofValue = proof.proofValue // base64url encoded
  const proofValueBytes = base64url.decode(proofValue)
  // console.log(proofValueBytes.length);
  // check header bytes are: 0xd9, 0x5d, and 0x00
  if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x00) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(proofValueBytes.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  const [baseSignature, proofPublicKey, hmacKey, signatures, mandatoryPointers] = decodeThing
  // setup HMAC stuff
  const hmac = await createHmac(hmacKey)
  const labelMapFactoryFunction = createHmacIdLabelMapFunction(hmac)

  const groups = {
    mandatory: mandatoryPointers
  }
  const stuff = await canonicalizeAndGroup(document, labelMapFactoryFunction, groups,
    { documentLoader: options.documentLoader })
  const mandatoryMatch = stuff.groups.mandatory.matching
  const mandatoryNonMatch = stuff.groups.mandatory.nonMatching
  // Check baseSignature;
  // canonize proof configuration and hash it
  const proofConfig = proof
  proofConfig['@context'] = document['@context']
  delete proofConfig.proofValue // Don't forget to remove this
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })
  const proofHash = sha256(proofCanon)
  // console.log(`proofHash: ${bytesToHex(proofHash)}`)
  const mandatoryCanon = [...mandatoryMatch.values()].join('')
  const mandatoryHash = sha256(mandatoryCanon)
  // console.log(`mandatoryHash: ${bytesToHex(mandatoryHash)}`)
  const signData = concatBytes(proofHash, proofPublicKey, mandatoryHash)
  let verificationResult = p256.verify(baseSignature, sha256(signData), pubKey)
  // console.log(`baseSignature verified: ${verificationResult}`)
  // Check each non-mandatory nquad signature
  const nonMandatory = [...mandatoryNonMatch.values()]
  nonMandatory.forEach((value, index) => {
    const sigVerified = p256.verify(signatures[index], sha256(value), proofPublicKey.slice(2))
    // console.log(`Signature ${index} verified: ${sigVerified}`)
    verificationResult &&= sigVerified
  })
  return verificationResult
}
