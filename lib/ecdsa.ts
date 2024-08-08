import { JWKKeyPair, MultikeyPair, MultikeyPairBinary, Ecdsa256Preambles, Ecdsa384Preambles, CryptoKeyClasses } from "./common.ts";
import * as secp256k1 from 'https://deno.land/x/secp256k1/mod.ts';

function hexToUint8Array(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error("Hex string must have an even length");
    }
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        array[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return array;
}



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
 * @param x - x value for the elliptical curve
 * @param d - d (private) value for the elliptical curve
 * @param y - y value for the elliptical curve
 * @returns 
 */
export function convertJWKCryptoValues(x: Uint8Array, d: Uint8Array | undefined, y?: Uint8Array): MultikeyPairBinary {
    console.log(x);
    console.log(y);

    if (y === undefined) {
        throw new Error("ECDSA encoding requires a 'y' value.");
    }
    // Compression means adding a new byte at the start of the 'x' value depending on the parity of 'y'
    const even = (y[y.length - 1] % 2 === 0) ? 0x02 : 0x03;
    const cx = new Uint8Array([even, ...x]);

    console.log(cx);

    //-----
    // const compressedPublicKey = '02e8d8cf85e7bd4c249fd54daf9883467e87c57c000aa33d0e67dedd431e81832c';
    // const compressedKeyArray = Uint8Array.from(hexToUint8Array(compressedPublicKey));

    // const uncompressedPublicKey = secp256k1.getPublicKey(compressedKeyArray, false);


    const ux = secp256k1.getPublicKey(d, false);
    console.log(ux);

    /** Just debugging here!!! */
    Deno.exit();

    return {
        public: cx,
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
 * @param _cl - unused in this function, just a placeholder
 * @param xb - binary version of the x value for the elliptical curve
 * @param db - binary version of the d value for the elliptical curve
 * @returns 
 */
export function convertCryptoToJWK(cl: CryptoKeyClasses, x: Uint8Array, d?: Uint8Array): JWKKeyPair {
    // To uncompress



    return {
        public: {
        }
    };
}


/*
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

// Example compressed key
const compressedKey = '02a1633caf...'; // Replace with your key

// Convert to a buffer
const compressedKeyBuffer = Buffer.from(compressedKey, 'hex');

// Decompress the key
const keyPair = ec.keyFromPublic(compressedKeyBuffer, 'hex');
const uncompressedKey = keyPair.getPublic(false, 'hex'); // false for uncompressed

console.log('Uncompressed Key:', uncompressedKey);

*/
