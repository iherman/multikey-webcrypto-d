/**
 * Conversion to and from [Multikey format](https://www.w3.org/TR/controller-document/#multikey) from
 * JWK or WebCrypto for the three EC curves that are defined for Verifiable Credentials: [ECDSA with P-256 and P-384](https://www.w3.org/TR/vc-di-ecdsa/#multikey) 
 * and [EDDSA](https://www.w3.org/TR/vc-di-eddsa/#multikey).
 * 
 * @package
 */

import * as convert                             from './lib/convert.ts';
import type { JWKKeyPair, Multikey, Multibase } from './lib/common.ts';
export type { JWKKeyPair, Multikey, Multibase}  from './lib/common.ts';

// This type guard function is reused at two different places, better factor it out...
// deno-lint-ignore no-explicit-any
function isMultikeyPair(obj: any): obj is Multikey {
    return (obj as Multikey).publicKeyMultibase !== undefined;
}

/* =========================================================================================
Converting multikeys to JWK
========================================================================================= */

/**
 * Convert a multikey pair to JWK. This function decodes the multikey data
 * into a binary buffer, checks the preambles and invokes the crypto specific converter functions 
 * (depending on the preamble values) that do the final conversion from the binary data to JWK.
 * 
 * Works for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.
 * 
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function multikeyToJWK(keys: Multikey): JWKKeyPair;
export function multikeyToJWK(keys: Multibase): JsonWebKey;
export function multikeyToJWK(keys: Multikey | Multibase): JWKKeyPair | JsonWebKey {
    const input: Multikey = isMultikeyPair(keys) ? keys as Multikey : { publicKeyMultibase: keys };
    const jwk_keys = convert.multikeyToJWK(input);
    if (isMultikeyPair(keys)) {
        return jwk_keys;
    } else {
        return jwk_keys.publicKey;
    }
}

/* =========================================================================================
Converting multikeys to WebCrypto
========================================================================================= */

/**
 * Convert a multikey pair to Web Crypto. This function decodes the multikey data into JWK using the
 * `multikeyToJWK` function, and imports the resulting keys into Web Crypto.
 * 
 * Works for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.
 * 
 * Note that, because WebCrypto methods are asynchronous, so is this function.
 * 
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 * @async
 */
export async function multikeyToCrypto(keys: Multikey): Promise<CryptoKeyPair>;
export async function multikeyToCrypto(keys: Multibase): Promise<CryptoKey>;
export async function multikeyToCrypto(keys: Multikey | Multibase): Promise<CryptoKeyPair | CryptoKey> {
    const input: Multikey = isMultikeyPair(keys) ? keys as Multikey : { publicKeyMultibase: keys };
    const jwkPair: JWKKeyPair = multikeyToJWK(input);

    const algorithm: { name: string, namedCurve ?: string } = { name : "" };

    // We have to establish what the algorithm type is from the public jwk
    switch (jwkPair.publicKey.kty) {
        case 'EC':
            algorithm.name = "ECDSA";
            algorithm.namedCurve = jwkPair.publicKey.crv; 
            break;
        case 'OKP':
            algorithm.name = "Ed25519";
            break;
        default:
            // In fact, this does not happen; the JWK comes from our own
            // generation, that raises an error earlier in this case.
            // But this keeps typescript happy...
            throw new Error("Unknown kty value for the JWK key");
    }

    const publicKey = await crypto.subtle.importKey("jwk", jwkPair.publicKey, algorithm, true, ["verify"]);
    if (isMultikeyPair(keys)) {
        if (jwkPair.privateKey !== undefined) {
            const privateKey = await crypto.subtle.importKey("jwk", jwkPair.privateKey, algorithm, true, ["sign"]);
            return { publicKey, privateKey } as CryptoKeyPair;
        } else {
            throw new Error("Unknown privateKey for the JWK key; something went wrong");
        }
    } else {
        return publicKey;
    }
}

/* =========================================================================================
Converting JWK to multikeys
========================================================================================= */

/**
 * Convert a JWK Key pair to Multikeys. This function decodes the JWK keys, finds out which binary key it encodes
 * and, converts the key to the multikey versions depending on the exact curve.
 * 
 * Note that the code does not check (yet?) all combination of JWK pairs and fields for possible errors, only
 * those that would lead to error in this package. E.g., it does not check whether the x (and possibly y) values
 * are identical in the secret and private JWK keys.
 * 
 * Works for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.
 * 
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function JWKToMultikey(keys: JWKKeyPair): Multikey;

/**
 * Overloaded version of the conversion function for a single (public) key in JWK, returning the generated Multikey.
 * @param keys
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function JWKToMultikey(keys: JsonWebKey): Multibase;

// Implementation of the overloaded functions
export function JWKToMultikey(keys: JWKKeyPair | JsonWebKey): Multikey | Multibase {
    // deno-lint-ignore no-explicit-any
    function isJWKKeyPair(obj: any): obj is JWKKeyPair {
        return (obj as JWKKeyPair).publicKey !== undefined;
    }
    const input: JWKKeyPair = isJWKKeyPair(keys) ? keys : {publicKey: keys};
    const m_keys = convert.JWKToMultikey(input);
    if (isJWKKeyPair(keys)) {
        return m_keys;
    } else {
        return m_keys.publicKeyMultibase;
    }
}

/* =========================================================================================
Converting WebCrypto to multikeys
========================================================================================= */

/**
 * Convert a Crypto Key pair to Multikeys. This function exports the cryptokeys into a JWK Key pair,
 * and uses the `JWKToMultikey` function.
 * 
 * Works for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.
 *
 * Note that, because WebCrypto methods are asynchronous, so is this function.
 * 
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 * @async
 */
export async function cryptoToMultikey(keys: CryptoKeyPair): Promise<Multikey>;
export async function cryptoToMultikey(keys: CryptoKey): Promise<Multibase>;
export async function cryptoToMultikey(keys: CryptoKeyPair | CryptoKey): Promise<Multikey | Multibase> {
    // deno-lint-ignore no-explicit-any
    function isCryptoKeyPair(obj: any): obj is CryptoKeyPair {
        return (obj as CryptoKeyPair).publicKey !== undefined;
    }
    const isPair = isCryptoKeyPair(keys);

    const publicKeyCr: CryptoKey = isPair ? keys.publicKey : keys;
    const privateKeyCr: CryptoKey | undefined = isPair ? keys.privateKey : undefined;

    // Generate the JWK version of the cryptokeys: 
    const jwkKeyPair: JWKKeyPair = {
        publicKey: await crypto.subtle.exportKey("jwk", publicKeyCr),
        privateKey: (isPair && privateKeyCr !== undefined) ? await crypto.subtle.exportKey("jwk", privateKeyCr) : undefined,
    }

    // Ready for conversion
    const output: Multikey = JWKToMultikey(jwkKeyPair);

    // Return the right version
    if (isPair) {
        return output;
    } else {
        return output.publicKeyMultibase;
    }
}

