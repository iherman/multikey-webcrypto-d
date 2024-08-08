import * as utils from "./lib/utils.ts";
import { JWKKeyPair, MultikeyPair, Multikey, isJWKKeyPair, isMultikeyPair } from './lib/common.ts';
export type { JWKKeyPair, MultikeyPair, Multikey }                          from './lib/common.ts';

/**
 * Generic function to convert a multikey pair to JWK. This function decodes the multikey data
 * into a binary buffer, checks the preambles and invokes the crypto specific converter functions 
 * (depending on the preamble values) that do the final
 * conversion from the binary data to JWK.
 * 
 * Works for ecdsa (both P-384 and P-256), and eddsa.
 * 
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function MultikeyToJWK(keys: Multikey): JsonWebKey;
export function MultikeyToJWK(keys: MultikeyPair): JWKKeyPair;
export function MultikeyToJWK(keys: MultikeyPair | Multikey): JWKKeyPair | JsonWebKey {
    const input: MultikeyPair = isMultikeyPair(keys) ? keys as MultikeyPair : {publicKeyMultibase: keys};
    const jwk_keys = utils.MultikeyToJWK(input);
    if (isMultikeyPair(keys)) {
        return jwk_keys;
    } else {
        return jwk_keys.public;
    }
}

/**
 * Convert JWK Key pair to Multikeys. This function decodes the JWK keys, finds out which binary key it encodes
 * and converts the key to the multikey versions depending on the exact curve.
 * 
 * Note that the code does not check (yet?) all combination of the JWK pairs where they would be erroneous, only
 * those that would lead to error in this cose. E.g., it does not check whether the x (and possibly y) values
 * are identical in the secret and private JWK keys.
 * 
 * Works for ecdsa (both P-384 and P-256), and eddsa.

 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function JWKToMultikey(keys: JsonWebKey): Multikey;
export function JWKToMultikey(keys: JWKKeyPair): MultikeyPair;
export function JWKToMultikey(keys: JWKKeyPair | JsonWebKey): MultikeyPair | Multikey {
    const input: JWKKeyPair = isJWKKeyPair(keys) ? keys : {public: keys};
    const m_keys = utils.JWKToMultikey(input);
    if (isJWKKeyPair(keys)) {
        return m_keys;
    } else {
        return m_keys.publicKeyMultibase;
    }
}
