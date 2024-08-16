/**
 * Common types, conversion functions and Multikey conversion utilities for the rest of the code. 
 * @module
 */

import * as eddsa from "./eddsa";
import * as ecdsa from "./ecdsa";

/**
 * Public/secret pair of JWK instances
 */
export interface JWKKeyPair {
    public: JsonWebKey;
    secret?: JsonWebKey;
}

/** 
 * Type for a Multibase
 * 
 * One day this could become a string with a fixed regexp...
 */
export type Multibase = string;

/**
 * Pair of keys in Multibase encoding. Using the field names as defined in the 
 * [Multikey specification](https://www.w3.org/TR/controller-document/#multikey).
 */
export interface Multikey {
    publicKeyMultibase:  Multibase;
    secretKeyMultibase?: Multibase;
}

/**
 * Same as the Multikey, but decoded and without the preambles. I.e., just the bare key values.
 */
export interface MultikeyBinary {
    public:  Uint8Array;
    secret?: Uint8Array
}

/************************************************************************* */
/* Values to handle the various preamble bytes for the different key types */
/************************************************************************* */

/**
 * Names for the various crypto curve
 */
export enum CryptoCurves {
    ECDSA_384 = "secp384r1",
    ECDSA_256 = "secp256r1",
    EDDSA     = "ed25519"
}

/**
 * Names for the key types
 */
export enum CryptoKeyTypes {
    PUBLIC = "public",
    SECRET = "secret"
}

/************************************* Preambles  ***************************/
/** 
 * Type used for preambles, which are, so far, a single pair of numbers. 
 */
export type Preamble<T> = [T,T];

/**
 * Each crypto class has two preambles, one for the public and one for the secret keys
 */
interface MultikeyPreambles {
    public: Preamble<number>,
    secret: Preamble<number>,
}

/**
 * Preamble value for EDDSA, a.k.a. `ed25519` curve
 */
export const EddsaPreambles: MultikeyPreambles = {
    public: [0xed, 0x01],
    secret: [0x80, 0x26],
};

/**
 * Preamble for ECDSA `P-256`, a.k.a. `secp256r1` curve
 */
export const Ecdsa256Preambles: MultikeyPreambles = {
    public: [0x80, 0x24],
    secret: [0x86, 0x26],
}

/**
 * Preamble for ECDSA `P-384`, a.k.a. `secp384r1` curve
 */
export const Ecdsa384Preambles: MultikeyPreambles = {
    public: [0x81, 0x24],
    secret: [0x87, 0x26],
};



/************************************ Converter tables **********************************/
// At various place in the code there is a choice to be made from preambles to specific curves
// and back. Better to encode these in conversion tables rather than build them in the code,
// this makes things less error-prone 

/**
 * Type definition for the table mapping preambles to a specific curve.
 */
export type ClassToPreamble = {
    [key in CryptoCurves]: MultikeyPreambles;
};

/**
 * What preambles must be used for a Curve?
 */
export const classToPreamble: ClassToPreamble = {
    [CryptoCurves.EDDSA]:     EddsaPreambles,
    [CryptoCurves.ECDSA_256]: Ecdsa256Preambles,
    [CryptoCurves.ECDSA_384]: Ecdsa384Preambles,
};

/**
 * Type definition for the table mapping curves to their decoder functions (i.e., mapping the Multikey to JWK).
 */
export type ClassToDecoder = {
    [key in CryptoCurves]: (curve: CryptoCurves, x: Uint8Array, d?: Uint8Array) => JWKKeyPair;
}

/**
 * What coder function must be used to convert from Multikey to JWK (data)?
 */
export const classToDecoder: ClassToDecoder = {
    [CryptoCurves.EDDSA]:     eddsa.multikeyBinaryToJWK,
    [CryptoCurves.ECDSA_256]: ecdsa.multikeyBinaryToJWK,
    [CryptoCurves.ECDSA_384]: ecdsa.multikeyBinaryToJWK,
};

/**
 * Type definition for the table mapping curves to their encoder functions (i.e., mapping the JWK to Multikey).
 */
export type ClassToEncoder = {
    [key in CryptoCurves]: (curve: CryptoCurves, x: Uint8Array, d: Uint8Array | undefined, _y?: Uint8Array) => MultikeyBinary
}

/**
 * What coder function must be used to convert from JWK to Multikey?
 */
export const classToEncoder: ClassToEncoder = {
    [CryptoCurves.EDDSA]:     eddsa.JWKToMultikeyBinary,
    [CryptoCurves.ECDSA_256]: ecdsa.JWKToMultikeyBinary,
    [CryptoCurves.ECDSA_384]: ecdsa.JWKToMultikeyBinary,
};

/**
 * List of possible ECDSA Curves. Having this here declaratively may make it easier if
 * in the future, a new curve is added to the family (P-512)?
 */
export const ECDSACurves: CryptoCurves[] = [CryptoCurves.ECDSA_256, CryptoCurves.ECDSA_384];

/**
 * This is an internal type, used for the implementation: return the crypto curve and type from a preamble.
 * 
 * So far, I have not yet found a way to encode that in a simple table, hence the separate function.
 */
export interface CryptoKeyData {
    crCurve: CryptoCurves,
    crType:  CryptoKeyTypes,
}

/**
 * Classify the crypto key based on the multikey preamble characters that are at the start of the code. 
 * These are two binary numbers, signalling the crypto category (`ecdsa` or `eddsa`) and, in the former case, 
 * the additional reference to the exact curve.
 * 
 * @param preamble 
 * @returns 
 */
export function preambleToCryptoData(preamble: Preamble<number>): CryptoKeyData {
    // Ugly but effective and simple trick to compare two arrays
    const eq = (a: Preamble<number>, b: Preamble<number>): boolean => JSON.stringify(a) === JSON.stringify(b);

    if (preamble.length !== 2) {
        throw new Error(`${preamble} is not valid, it should have a size of exactly 2.`);
    }

    // The real classification...
    if (eq(preamble, Ecdsa256Preambles.secret)) {
        return {
            crCurve: CryptoCurves.ECDSA_256,
            crType:  CryptoKeyTypes.SECRET,
        };
    } else if (eq(preamble, Ecdsa256Preambles.public)) {
        return {
            crCurve: CryptoCurves.ECDSA_256,
            crType:  CryptoKeyTypes.PUBLIC,
        };
    } else if (eq(preamble, Ecdsa384Preambles.secret)) {
        return {
            crCurve: CryptoCurves.ECDSA_384,
            crType:  CryptoKeyTypes.SECRET,
        };
    } else if (eq(preamble, Ecdsa384Preambles.public)) {
        return {
            crCurve: CryptoCurves.ECDSA_384,
            crType:  CryptoKeyTypes.PUBLIC,
        };
    } else if (eq(preamble, EddsaPreambles.secret)) {
        return {
            crCurve: CryptoCurves.EDDSA,
            crType:  CryptoKeyTypes.SECRET,
        };
    } else if (eq(preamble, EddsaPreambles.public)) {
        return {
            crCurve: CryptoCurves.EDDSA,
            crType:  CryptoKeyTypes.PUBLIC,
        };
    } else {
        throw new Error(`${preamble} is unknown. Should refer to secret or private eddsa or ecdsa (the latter with P-256 or P-384)`);
    }
}
