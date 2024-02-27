import { concatBytes } from '@noble/hashes/utils' // bytesToHex is in here too
import { base58btc } from 'multiformats/bases/base58'
import jsonld from 'jsonld'
import { randomBytes } from './randomBytes.js'
import { sha256 } from '@noble/hashes/sha256'
import { p256 } from '@noble/curves/p256'
import { createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup } from
  './primitives.js'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

const PRE_MKEY_P256 = new Uint8Array([0x80, 0x24])
/**
 * sign a base document (credential) with ECDSA-SD procedures. This is done by an
 * issuer and permits the recipient, the holder, the freedom to selectively disclose
 * "statements" extracted from the document to a verifier within the constraints
 * of the mandatory disclosure requirements imposed by the issuer.
 *
 * @param {Object} document - The unsigned credential
 * @param {Object} keyPair - The issuers private/public key pair
 * @param {Uint8Array} keyPair.priv - Byte array for the P256 private key without multikey prefixes
 * @param {Uint8Array} keyPair.pub - Byte array for the P256 public key without multikey prefixes
 * @param {Array} mandatoryPointers - An array of mandatory pointers in JSON pointer format
 * @param {Object} options - A variety of options to control signing and processing
 * @param {Object} options.proofConfig - proof configuration options without `@context`
 *  field. Optional. This will be generated with current date information and
 *  did:key verification method otherwise.
 * @param {Uint8Array} options.hmacKey - A byte array for the HMAC key. Optional. A
 *   cryptographically secure random value will be generated if not specified.
 * @param {Object} options.proofKeyPair - A proof specific P256 key pair. Must
 *   be unique for each call to signBase. Optional. A unique key pair will be
 *   generated if not specified.
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function signBase (document, keyPair, mandatoryPointers, options) {
  // Set up proof configuration and canonize
  let proofConfig = {}
  if (options.proofConfig !== undefined) {
    proofConfig = Object.assign({}, options.proofConfig)
  } else { // Create the proofConfig
    proofConfig.type = 'DataIntegrityProof'
    proofConfig.cryptosuite = 'ecdsa-sd-2023'
    const nd = new Date()
    proofConfig.created = nd.toISOString()
    const publicKeyMultibase = base58btc.encode(concatBytes(PRE_MKEY_P256, keyPair.pub))
    proofConfig.verificationMethod = 'did:key:' + publicKeyMultibase + '#' + publicKeyMultibase
    proofConfig.proofPurpose = 'assertionMethod'
  }
  proofConfig['@context'] = document['@context']
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })

  // Check for HMAC key and generate if not present
  let hmacKey
  if (options.hmacKey !== undefined) {
    hmacKey = options.hmacKey
  } else {
    hmacKey = randomBytes(32)
  }
  // Check for proofKeyPair and generate if not present
  let proofKeyPair = {}
  if (options.proofKeyPair !== undefined) {
    proofKeyPair = options.proofKeyPair
  } else {
    proofKeyPair.priv = p256.utils.randomPrivateKey()
    proofKeyPair.pub = p256.getPublicKey(proofKeyPair.priv)
  }
  // **Transformation Step**
  const hmacFunc = await createHmac(hmacKey)
  const labelMapFactoryFunction = createHmacIdLabelMapFunction(hmacFunc)
  const groups = { mandatory: mandatoryPointers }
  const stuff = await canonicalizeAndGroup(document, labelMapFactoryFunction, groups, { documentLoader: options.documentLoader })
  const mandatory = stuff.groups.mandatory.matching
  const nonMandatory = stuff.groups.mandatory.nonMatching
  // **Hashing Step**
  const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8
  // console.log(`Proof hash: ${bytesToHex(proofHash)}`)
  const mandatoryHash = sha256([...mandatory.values()].join(''))
  // console.log(`mandatory hash: ${bytesToHex(mandatoryHash)}`)
  // console.log([...mandatory.values()])s
  // **Signatures**
  const signatures = []
  nonMandatory.forEach(function (value, key) {
    const msgHash = sha256(value) // Hash is done outside of the algorithm in noble/curve case.
    const signature = p256.sign(msgHash, proofKeyPair.priv)
    signatures.push(signature.toCompactRawBytes())
  })
  const prefixedProofKey = concatBytes(PRE_MKEY_P256, proofKeyPair.pub)
  const signData = concatBytes(proofHash, prefixedProofKey, mandatoryHash)
  const baseSignature = p256.sign(sha256(signData), keyPair.priv).toCompactRawBytes()
  // **Serialization**
  let proofValue = new Uint8Array([0xd9, 0x5d, 0x00])
  const components = [baseSignature, prefixedProofKey, hmacKey, signatures, mandatoryPointers]
  const cborThing = await cbor.encodeAsync(components)
  proofValue = concatBytes(proofValue, cborThing)
  const baseProof = base64url.encode(proofValue)

  // Construct and Write Signed Document
  const signedDocument = klona(document)
  delete proofConfig['@context']
  signedDocument.proof = proofConfig
  signedDocument.proof.proofValue = baseProof
  return signedDocument
}
