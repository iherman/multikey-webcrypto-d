import { Uint8ToMultikey, Uint8ArrayToBase64Url } from './utils.ts';
import { JWKKeyPair, MultikeyPair, Ecdsa256Preambles, Ecdsa384Preambles } from "./types.ts";


export function MultikeyToJWK(public_data: Uint8Array, private_data?: Uint8Array): JWKKeyPair {
    return {
        public: {
        }
    };
}
