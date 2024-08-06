import { Uint8ToMultikey, Uint8ArrayToBase64Url } from './utils.ts';
import { JWKKeyPair, MultikeyPair, MultikeyPairBinary, Ecdsa256Preambles, Ecdsa384Preambles, CryptoKeyClasses } from "./common.ts";


export function convertCryptoToJWK(cl: CryptoKeyClasses, x: Uint8Array, d?: Uint8Array): JWKKeyPair {
    return {
        public: {
        }
    };
}
export function convertJWKCryptoValues(x: Uint8Array, d: Uint8Array | undefined, _y?: Uint8Array): MultikeyPairBinary {
    return {
        public: x,
        secret: d
    };
}
