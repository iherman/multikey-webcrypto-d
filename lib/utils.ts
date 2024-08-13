import {
    JWKKeyPair, MultikeyPair, Multikey, Preamble,
    CryptoKeyClasses, CryptoKeyTypes, CryptoKeyData,
    MultikeyPairBinary,
    classToPreamble, classToDecoder, classToEncoder,
    preambleToCryptoData 
} from "./common.ts";

import * as base58 from './encodings/base58/index.js';
import * as base64 from "./encodings/base64.ts";

interface MultikeyData {
    preamble: Preamble<number>,
    key_binary: Uint8Array;
}

/****************************************************************************************/
/* The real converter functions                                                         */
/****************************************************************************************/
/**
 * Generic function to convert a multikey pair to JWK. This function decodes the multikey data
 * into a binary buffer, checks the preambles and invokes the crypto specific converter functions 
 * (depending on the preamble values) that do the final
 * conversion from the binary data to JWK.
 * 
 * Works for ecdsa (both P-384 and P-256), and eddsa.
 * 
 * @param keys 
 * @returns 
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function MultikeyToJWK(keys: MultikeyPair): JWKKeyPair {
    // Separate the preamble of a multikey from the key value
    const convertBinary = (key: Multikey): MultikeyData => {
        // Check whether the first character is a 'z' before removing it
        if (key[0] === 'z') {
            const unencoded_key: Uint8Array = base58.decode(key.slice(1));
            return {
                preamble   : [unencoded_key[0], unencoded_key[1]],
                key_binary : unencoded_key.slice(2),
            };
        } else {
            throw new Error(`"${key}" is not encoded as required (first character should be a 'z')`);
        }
    };

    const public_binary = convertBinary(keys.publicKeyMultibase);
    const public_data: CryptoKeyData = preambleToCryptoData(public_binary.preamble);
    if (public_data.crType !== CryptoKeyTypes.PUBLIC) {
        throw new Error(`"${keys.publicKeyMultibase}" has the wrong preamble (should refer to a public key).`);
    }

    const converter = classToDecoder[public_data.crClass];

    // We have to repeat the previous steps for a secret key, if applicable, before converting the result into a JWK pair,
    // A check is made on the fly to see that the keys are compatible in terms of crypto methods
    if (keys.secretKeyMultibase) {
        const secret_binary = convertBinary(keys.secretKeyMultibase);
        const secret_data: CryptoKeyData = preambleToCryptoData(secret_binary.preamble);

        if (secret_data.crClass !== public_data.crClass) {
            throw new Error(`Private and secret keys have different crypto methods`);
        } else if (secret_data.crType !== CryptoKeyTypes.PRIVATE) {
            throw new Error(`"${keys.secretKeyMultibase}" has the wrong preamble (should refer to a secret key).`);
        }

        // Everything seems to be fine
        return converter(public_data.crClass, public_binary.key_binary, secret_binary.key_binary);
    } else {
        return converter(public_data.crClass, public_binary.key_binary);
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
 */
export function JWKToMultikey(keys: JWKKeyPair): MultikeyPair {
    // Internal function for the common last step of encoding a multikey
    const convertMultikey = (val: Uint8Array, preamble: Preamble<number>): string => {
        const val_mk = new Uint8Array([...preamble, ...val]);
        return 'z' + base58.encode(val_mk);
    }

    const convertJWKField = (val: string | undefined): Uint8Array | undefined => {
        if (val === undefined) {
            return undefined
        } else {
            return base64.decode(val);
        }
    }

    // Find out the key class, will be used for branching later: is it ECDSA or EDDSA and, if the former,
    // which one?
    const keyClass = (key: JsonWebKey): CryptoKeyClasses => {
        if (key.kty) {
            if (key.kty === "EC") {
                switch (key.crv) {
                    case "P-256": return CryptoKeyClasses.ECDSA_256;
                    case "P-384": return CryptoKeyClasses.ECDSA_384;
                    default: throw new Error(`Unknown crv value for an ecdsa key (${key.crv})`);
                }
            } else if (key.kty === "OKP") {
                if (key.crv === "Ed25519") {
                    return CryptoKeyClasses.EDDSA
                } else {
                    throw new Error(`Unknown crv value for an OKP key (${key.crv})`)
                }
            } else {
                throw new Error(`Unknown kty value for a key (${key.kty})`)
            }
        } else {
            throw new Error(`No kty value for the key (${JSON.stringify(key)})`)
        }
    };

    const public_key_class = keyClass(keys.public);

    // The secret key class is calculated, but this is just for checking; the two must be identical...
    if (keys.secret !== undefined) {
        const secret_key_class = keyClass(keys.secret);
        if (public_key_class !== secret_key_class) {
            throw new Error(`Public and private keys are of a different class  (${JSON.stringify(keys)})`);
        }
    }

    // The cryptokey values are x, y (for ecdsa), and d (for the secret key).
    // Each of these are base 64 encoded strings; what we need is the 
    // binary versions thereof.
    const x: Uint8Array | undefined = convertJWKField(keys.public.x);
    if (x === undefined) {
        throw new Error(`x value is missing from public key  (${JSON.stringify(keys.public)})`);
    }
 
    const y: Uint8Array | undefined = convertJWKField(keys.public.y);
    if ((public_key_class === CryptoKeyClasses.ECDSA_256 || public_key_class === CryptoKeyClasses.ECDSA_384) && y === undefined) {
        throw new Error(`y value is missing from public key for ECDSA  (${JSON.stringify(keys.public)})`);
    }

    const d: Uint8Array | undefined = (keys.secret) ? convertJWKField(keys.secret.d) : undefined;
    if (keys.secret && d === undefined) {
        throw new Error(`d value is missing from private key  (${JSON.stringify(keys)})`);
    }

    const converter = classToEncoder[public_key_class]
    const final_binary: MultikeyPairBinary = converter(public_key_class, x, d, y);

    // We have the binary version of the multikey values, this must be converted into real multikey.
    // This means adding a preamble and convert to base58.
    const preambles = classToPreamble[public_key_class];
    const output: MultikeyPair = {
        publicKeyMultibase : convertMultikey(final_binary.public, preambles.public)
    }
    if (final_binary.secret !== undefined) {
        output.secretKeyMultibase = convertMultikey(final_binary.secret, preambles.secret);
    }
    return output;
}




