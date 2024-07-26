import {
    JWKKeyPair, MultikeyPair, Multikey, Preamble,
    EddsaPreambles, Ecdsa256Preambles, Ecdsa384Preambles,
    CryptoKeyClasses, CryptoKeyTypes, CryptoKeyData
} from "./types.ts";
import * as eddsa from "./eddsa.ts";
import * as ecdsa from "./ecdsa.ts";

import { base58Encode, base58Decode } from './encodings/base58/index.js';
import { base64UrlToUint8Array, Uint8ArrayToBase64Url } from "./encodings/base64.ts";

interface MultikeyBinaryData {
    preamble: Preamble<number>,
    key_binary: Uint8Array;
}


export function Uint8ToMultikey(val: string, preamble: Preamble<number>): string {
    const val_bin: Uint8Array = base64UrlToUint8Array(val);
    const val_mk = new Uint8Array([...preamble, ...val_bin]);
    return 'z' + base58Encode(val_mk);
}


/**
 * Generic function to convert a multikey pair to JWK. This function primarily decodes the multikey data
 * into a binary buffer, checks the preambles and invokes the crypto specific converter functions that do the final
 * conversion from the binary data to JWK.
 * 
 * @param keys 
 * @returns 
 */
export function MultikeyPairToJWK(keys: MultikeyPair): JWKKeyPair {
    const MultikeyBinary = (key: Multikey): MultikeyBinaryData => {
        // Check whether the first character is a 'z' before removing it
        if (key[0] === 'z') {
            const unencoded_key: Uint8Array = base58Decode(key.slice(1));
            return {
                preamble: [unencoded_key[0], unencoded_key[1]],
                key_binary: unencoded_key.slice(2),
            };
        } else {
            throw new Error(`"${key}" is not encoded as required (first character should be a 'z')`);
        }
    };

    const public_binary = MultikeyBinary(keys.publicKeyMultibase);
    const public_data: CryptoKeyData = classifyKey(public_binary.preamble);
    if (public_data.crType !== CryptoKeyTypes.PUBLIC) {
        throw new Error(`"${keys.publicKeyMultibase}" has the wrong preamble (should refer to a public key).`);
    }

    const converter = ((): ((pub: Uint8Array, sec?: Uint8Array) => JWKKeyPair) => {
        switch (public_data.crClass) {
            case CryptoKeyClasses.ECDSA_384:
            case CryptoKeyClasses.ECDSA_256: {
                return ecdsa.MultikeyToJWK;
            }
            case CryptoKeyClasses.EDDSA: {
                return eddsa.MultikeyToJWK;
            }
        }
    })();

    if (keys.secretKeyMultibase) {
        const secret_binary = MultikeyBinary(keys.secretKeyMultibase);
        const secret_data: CryptoKeyData = classifyKey(secret_binary.preamble);

        if (secret_data.crClass !== public_data.crClass) {
            throw new Error(`Private and secret keys have different crypto methods`);
        } else if (secret_data.crType !== CryptoKeyTypes.PRIVATE) {
            throw new Error(`"${keys.secretKeyMultibase}" has the wrong preamble (should refer to a secret key).`);
        }

        // Everything seems to be fine
        return converter(public_binary.key_binary, secret_binary.key_binary);
    } else {
        return converter(public_binary.key_binary);
    }
}


/*************************************************************************************************/
/*                                     Internal utilities                                        */
/*************************************************************************************************/
/**
 * Classify the crypto key based on the multikey preamble characters that are at the start of the code. 
 * These are two binary numbers, signalling the crypto class (ecdsa or eddsa) and, in the former case, 
 * the hash function.
 * 
 * @param preamble 
 * @returns 
 */
function classifyKey(preamble: Preamble<number>): CryptoKeyData {
    // Ugly but effective and simple trick to compare two arrays
    const eq = (a: Preamble<number>, b: Preamble<number>): boolean => JSON.stringify(a) === JSON.stringify(b);

    if (preamble.length !== 2) {
        throw new Error(`${preamble} is not valid, it should have a size of exactly 2.`);
    }

    // The real classification...
    if (eq(preamble, Ecdsa256Preambles.private)) {
        return {
            crClass: CryptoKeyClasses.ECDSA_256,
            crType: CryptoKeyTypes.PRIVATE,
        };
    } else if (eq(preamble, Ecdsa256Preambles.public)) {
        return {
            crClass: CryptoKeyClasses.ECDSA_256,
            crType: CryptoKeyTypes.PUBLIC,
        };
    } else if (eq(preamble, Ecdsa384Preambles.private)) {
        return {
            crClass: CryptoKeyClasses.ECDSA_384,
            crType: CryptoKeyTypes.PRIVATE,
        };
    } else if (eq(preamble, Ecdsa384Preambles.public)) {
        return {
            crClass: CryptoKeyClasses.ECDSA_384,
            crType: CryptoKeyTypes.PUBLIC,
        };
    } else if (eq(preamble, EddsaPreambles.private)) {
        return {
            crClass: CryptoKeyClasses.EDDSA,
            crType: CryptoKeyTypes.PRIVATE,
        };
    } else if (eq(preamble, EddsaPreambles.public)) {
        return {
            crClass: CryptoKeyClasses.EDDSA,
            crType: CryptoKeyTypes.PUBLIC,
        };
    } else {
        throw new Error(`${preamble} is unknown.`);
    }
}



