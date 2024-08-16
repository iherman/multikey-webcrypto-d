/**
 * Conversion to and from [Multikey format](https://www.w3.org/TR/controller-document/#multikey) from
 * JWK or WebCrypto for the three EC curves that are defined for Verifiable Credentials: [ECDSA with P-256 and P-384](https://www.w3.org/TR/vc-di-ecdsa/#multikey) 
 * and [EDDSA](https://www.w3.org/TR/vc-di-eddsa/#multikey).
 * 
 * @package
 */

import * as convert                            from './lib/convert';
import { JWKKeyPair, Multikey, Multibase }     from './lib/common';
export type { JWKKeyPair, Multikey, Multibase} from './lib/common';

// This type guard function is reused at two different places, better factor it out...
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

/**
 * Overloaded version of the conversion function for a single (public) key in Multikey, returning the generated JWK.
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function multikeyToJWK(keys: Multibase): JsonWebKey;

export function multikeyToJWK(keys: Multikey | Multibase): JWKKeyPair | JsonWebKey {
    const input: Multikey = isMultikeyPair(keys) ? keys as Multikey : { publicKeyMultibase: keys };
    const jwk_keys = convert.multikeyToJWK(input);
    if (isMultikeyPair(keys)) {
        return jwk_keys;
    } else {
        return jwk_keys.public;
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

/**
 * Overloaded version of the conversion function for a single (public) key in Multikey, returning the generated Crypto Key.
 * @param keys 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export async function multikeyToCrypto(keys: Multibase): Promise<CryptoKey>;

// Implementation of the overloaded functions
export async function multikeyToCrypto(keys: Multikey | Multibase): Promise<CryptoKeyPair | CryptoKey> {
    const input: Multikey = isMultikeyPair(keys) ? keys as Multikey : { publicKeyMultibase: keys };
    const jwkPair: JWKKeyPair = multikeyToJWK(input);

    const algorithm: { name: string, namedCurve ?: string } = { name : "" };

    // We have to establish what the algorithm type is from the public jwk
    switch (jwkPair.public.kty) {
        case 'EC':
            algorithm.name = "ECDSA";
            algorithm.namedCurve = jwkPair.public.crv; 
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

    const output: CryptoKeyPair = {
        publicKey : await crypto.subtle.importKey("jwk", jwkPair.public, algorithm, true, ["verify"]),
        privateKey : undefined,
    }
    if (jwkPair.secret != undefined) {
        output.privateKey = await crypto.subtle.importKey("jwk", jwkPair.secret, algorithm, true, ["sign"])
    }

    // Got the return, the type depends on the overloaded input type
    if (isMultikeyPair(keys)) {
        return output;
    } else {
        return output.publicKey;
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
    function isJWKKeyPair(obj: any): obj is JWKKeyPair {
        return (obj as JWKKeyPair).public !== undefined;
    }
    const input: JWKKeyPair = isJWKKeyPair(keys) ? keys : {public: keys};
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
 * Convert a Crypto Key pair to Multikeys. This function exports the Cryptokeys into a JWK Key pair,
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

/**
 * Overloaded version of the conversion function for a single (public) key in JWK, returning the generated Multikey.
 * @param keys
 * @throws - exceptions if something is incorrect in the incoming data
 */
export async function cryptoToMultikey(keys: CryptoKey): Promise<Multibase>;

// Implementation of the overloaded functions
export async function cryptoToMultikey(keys: CryptoKeyPair | CryptoKey): Promise<Multikey | Multibase> {
    function isCryptoKeyPair(obj: any): obj is CryptoKeyPair {
        return (obj as CryptoKeyPair).publicKey !== undefined;
    }
    const isPair = isCryptoKeyPair(keys);

    const input: CryptoKeyPair = isPair ? keys : { publicKey: keys, privateKey: undefined };

    // Generate the JWK version of the cryptokeys: 
    const jwkKeyPair: JWKKeyPair = {
        public: await crypto.subtle.exportKey("jwk", input.publicKey),
    }
    if (isPair && input.privateKey !== undefined) {
        jwkKeyPair.secret = await crypto.subtle.exportKey("jwk", input.privateKey);
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

