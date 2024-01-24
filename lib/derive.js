import { concatBytes } from '@noble/hashes/utils'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'
import {
  createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup, selectJsonLd,
  stripBlankNodePrefixes
} from './primitives.js'
import jsonld from 'jsonld'

/**
 * derive a selectively disclosed document (presentation) with ECDSA-SD procedures.
 * This is done by a holder, who has the option to selectively disclose non-mandatory
 * statements to a verifier.
 *
 * @param {Object} document - The signed base credential
 * @param {Array} selectivePointers - An array of selective pointers in JSON pointer format
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 */
export async function derive (document, selectivePointers, options) {
  const doc = klona(document)
  // parseBaseProofValue:
  const proof = doc.proof
  delete doc.proof // IMPORTANT: all work uses document without proof
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
  // Combine pointers and create reveal document
  const combinedPointers = mandatoryPointers.concat(selectivePointers)
  const revealDocument = selectJsonLd(doc, combinedPointers)

  const hmac = await createHmac(hmacKey)
  const labelMapFactoryFunction = createHmacIdLabelMapFunction(hmac)

  const groups = {
    mandatory: mandatoryPointers,
    selective: selectivePointers,
    combined: combinedPointers
  }
  const stuff = await canonicalizeAndGroup(doc, labelMapFactoryFunction, groups,
    { documentLoader: options.documentLoader })
  const combinedMatch = stuff.groups.combined.matching
  const mandatoryMatch = stuff.groups.mandatory.matching
  const mandatoryNonMatch = stuff.groups.mandatory.nonMatching // For reverse engineering
  const selectiveMatch = stuff.groups.selective.matching
  const combinedIndexes = [...combinedMatch.keys()]
  const nonMandatoryIndexes = [...mandatoryNonMatch.keys()]

  // Compute the "adjusted mandatory indexes" relative to their position in combined list
  const adjMandatoryIndexes = []
  mandatoryMatch.forEach((value, index) => {
    adjMandatoryIndexes.push(combinedIndexes.indexOf(index))
  })

  // Determine which signatures match a selectively disclosed statement.
  const adjSignatureIndexes = []
  selectiveMatch.forEach((value, index) => {
    const adjIndex = nonMandatoryIndexes.indexOf(index)
    if (adjIndex !== -1) {
      adjSignatureIndexes.push(adjIndex)
    }
  })
  const filteredSignatures = signatures.filter((value, index) => adjSignatureIndexes.includes(index))

  // Produce the verifier label map and minimize
  const deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads
  let canonicalIdMap = new Map()
  await jsonld.canonize(deskolemizedNQuads.join(''), {
    documentLoader: options.documentLoader,
    inputFormat: 'application/n-quads',
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: true,
    canonicalIdMap
  })
  canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap)
  const verifierLabelMap = new Map()
  const labelMap = stuff.labelMap
  canonicalIdMap.forEach(function (value, key) {
    verifierLabelMap.set(value, labelMap.get(key))
  })

  const newProof = Object.assign({}, proof)
  const compressLabelMap = new Map()
  verifierLabelMap.forEach(function (v, k) {
    const key = parseInt(k.split('c14n')[1])
    const value = base64url.decode(v)
    compressLabelMap.set(key, value)
  })

  //  Initialize a byte array, proofValue, that starts with the ECDSA-SD disclosure proof header
  //  bytes 0xd9, 0x5d, and 0x01.
  let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x01])
  const components = [baseSignature, proofPublicKey, filteredSignatures, compressLabelMap, adjMandatoryIndexes]
  const cborThing = await cbor.encodeAsync(components)
  derivedProofValue = concatBytes(derivedProofValue, cborThing)
  const derivedProofValueString = base64url.encode(derivedProofValue)
  newProof.proofValue = derivedProofValueString
  revealDocument.proof = newProof
  return revealDocument
}
