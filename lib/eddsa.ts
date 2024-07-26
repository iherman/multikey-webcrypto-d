import { Uint8ToMultikey } from './utils.ts'; 
import { JWKKeyPair, MultikeyPair, EddsaPreambles } from "./types.ts";
import { Uint8ArrayToBase64Url } from './base64.ts'; 


export function JWKToMultikey(pub: JsonWebKey, sec?: JsonWebKey): MultikeyPair {
    // First, handle the public key part
    // x is the base58url encoded representation of the public key
    const output: MultikeyPair = {
        publicKeyMultibase: Uint8ToMultikey(pub.x as string, EddsaPreambles.public),
    };

    // Second, handle the secret part, if available
    if (sec !== undefined) {
        output.secretKeyMultibase = Uint8ToMultikey(sec.d as string, EddsaPreambles.private);
    }
    return output;
}

export function MultikeyToJWK(public_data: Uint8Array, private_data?: Uint8Array): JWKKeyPair {
    const x: string = Uint8ArrayToBase64Url(public_data);
    const output: JWKKeyPair = {
        public: {
            kty: "OKP",
            crv: "Ed25519",
            x,
            key_ops: [
                "verify"
            ],
            ext: true
        }
    };

    if (private_data !== undefined) {
        const d: string = Uint8ArrayToBase64Url(private_data);
        output.private = {
            kty: "OKP",
            crv: "Ed25519",
            x,
            d,
            key_ops: [
                "sign"
            ],
            ext: true
        };
    }
    return output;
}
