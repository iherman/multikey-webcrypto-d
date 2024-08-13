import { JWKKeyPair, MultikeyPairBinary, CryptoKeyClasses } from "./common.ts";
import * as base64 from                                          "./encodings/base64.ts";

/**
 * Convert the Crypto values from JWK to the equivalent Multikey Pairs' binary data. 
 * The final encoding, with preambles, are done in the general level.
 * 
 * For ECDSA, the compressed form must be calculated, by adding an extra byte signaling which of the 
 * two possible 'y' values are used.
 * 
 * (The y value is set as optional in the signature but that is only to make TypeScript happy. A missing
 * value generates an error)
 * 
 * @param cl - choice between P-256 and P-384
 * @param x - x value for the elliptical curve
 * @param d - d (private) value for the elliptical curve
 * @param y - y value for the elliptical curve
 * @returns 
 */
export function convertJWKCryptoValues(cl: CryptoKeyClasses, x: Uint8Array, d: Uint8Array | undefined, y?: Uint8Array): MultikeyPairBinary {
    if (y === undefined) {
        throw new Error("ECDSA encoding requires a 'y' value.");
    }

    // console.log("Incoming 'x':", x);
    // console.log("Incoming 'y':", y);
    
    // const cx = compressPublicKey(cl, x, y);

    // // Check the round robin...
    // console.log("Compressed key:", cx);

    // const uc = uncompressPublicKey(cl, cx);

    // console.log("Generated 'x':", uc.x);
    // console.log("Generated 'y':", uc.y);

    return {
        public: compressPublicKey(cl, x, y),
        secret: d
    };
}

/**
 * Convert the multikey values to their JWK equivalents. The final `x` and `d` values are encoded
 * in base64 and then the relevant JWK structure are created
 * 
 * For EDDSA, this is a very straightforward operation by just encoding the values and plugging them into a
 * constant JWK structure. The interface is there to be reused by the ECDSA equivalent, which must 
 * do some extra processing.
 * 
 * @param cl - choice between P-256 and P-384
 * @param xb - binary version of the x value for the elliptical curve
 * @param db - binary version of the d value for the elliptical curve
 * @returns 
 */
export function convertCryptoToJWK(cl: CryptoKeyClasses, xb: Uint8Array, db?: Uint8Array): JWKKeyPair {
    // The extra complication with ECDSA: the multikey is the compressed 'x' value, the 'y' value
    // must be calculated.
    const uncompressed = uncompressPublicKey(cl, xb);
    const x = base64.encode(uncompressed.x);
    const y = base64.encode(uncompressed.y);
    const output: JWKKeyPair = {
        public: {
            kty: "EC",
            crv: (cl === CryptoKeyClasses.ECDSA_256) ? "P-256" : "P-384",
            x,
            y,
            key_ops: [
                "verify"
            ],
            ext: true,
        }
    };
    if (db !== undefined) {
        output.secret = {
            kty: "EC",
            crv: (cl === CryptoKeyClasses.ECDSA_256) ? "P-256" : "P-384",
            x,
            y,
            d : base64.encode(db),
            key_ops: [
                "sign"
            ],
            ext: true
        }
    }
    return output;
}

/************************************************************************
 * 
 * Internal utility functions. Some parts of the code below comes from
 * a Perplexity.ai prompt. (I wish there was a better documentation of the
 * packages instead...)
 *  
*************************************************************************/

import { p384 } from 'npm:@noble/curves/p384';
import { p256 } from 'npm:@noble/curves/p256';

// Utility function to convert Uint8Array to hex string
function uint8ArrayToHex(uint8Array: Uint8Array): string {
    return Array.from(uint8Array)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}

// Utility function to convert hex string to Uint8Array
function hexToUint8Array(hex: string): Uint8Array {
    const result = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        result[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return result;
}


// should be all with Uint8arrays
function compressPublicKey(cryptoClass: CryptoKeyClasses, x: Uint8Array, y: Uint8Array): Uint8Array {
    const xBigInt = BigInt(`0x${uint8ArrayToHex(x)}`);
    const yBigInt = BigInt(`0x${uint8ArrayToHex(y)}`);

    const point = (cryptoClass === CryptoKeyClasses.ECDSA_256) ? new p256.ProjectivePoint(xBigInt, yBigInt, 1n) : new p384.ProjectivePoint(xBigInt, yBigInt, 1n);

    // const point = new p384.ProjectivePoint(xBigInt, yBigInt, 1n);

    return point.toRawBytes(true);
    // return uint8ArrayToHex(compressedKey);
}


// should be all with Uint8arrays
function uncompressPublicKey(cryptoClass: CryptoKeyClasses, compressedKey: Uint8Array): { x: Uint8Array, y: Uint8Array, } {
    // const compressedKey = hexToUint8Array(xc);
    const point = (cryptoClass === CryptoKeyClasses.ECDSA_256) ? p256.ProjectivePoint.fromHex(compressedKey) : p384.ProjectivePoint.fromHex(compressedKey);
    const uncompressedKey = point.toRawBytes(false);

    const keyLength = (cryptoClass === CryptoKeyClasses.ECDSA_256) ? 32 : 48;

    const joinedXY = uncompressedKey.slice(1);
    const x = joinedXY.slice(0, keyLength);
    const y = joinedXY.slice(keyLength);

    return { x, y };
}

// function main(cryptoClass: CryptoKeyClasses) {

//     const x256 = hexToUint8Array('58a709c97cf8b0a829fa6f2f6614dfedc94f0fe106b59ac9e159e4e5fbca9e54');
//     const y256 = hexToUint8Array('1a261d024e97af845963f537aebf6015522c7c5fa878da2b01853435e7cb567a');

//     const x384 = hexToUint8Array('ec54b2e6292ee3b6497e34eb92e6226729bc7b683672ecaf285a89f95e04488848e992892482bccb3c9c6cd277cf32da');
//     const y384 = hexToUint8Array('3cdca473a412b1375348018e4406b0cb8772d533d8d351d6c8c4eff4e6c824ba449bcce6c85d5835922c7433f8ecaaa3');

//     const { x, y } = (cryptoClass === CryptoKeyClasses.ECDSA_256) ? { x: x256, y: y256 } : { x: x384, y: y384 };

//     console.log("x: ", x);
//     console.log("x: ", y);
//     const compressedKey = compressPublicKey(cryptoClass, x, y);
//     console.log("Compressed Key:", compressedKey);
//     const newXs = uncompressPublicKey(cryptoClass, compressedKey);
//     console.log("x: ", newXs.x);
//     console.log("y: ", newXs.y);
// }

// main(CryptoKeyClasses.ECDSA_384);
// generateKeyPair();
