import { JWKKeyPair, Multikey, JWKToMultikey, multikeyToJWK } from "../index";

/** ----------------------------- */

/************* Debugging help ***********/
// deno-lint-ignore no-explicit-any
export function str(inp: any): void {
    console.log(JSON.stringify(inp, null, 4));
}

/**
 * Convert a CryptoKey Pair into a JWK Pair. Not really used by these tools, but handy to have it to help debugging.
 * @param newPair 
 * @returns 
 */

async function toJWK(newPair: CryptoKeyPair): Promise<JWKKeyPair> {
    const publicKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.publicKey);
    const privateKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
    return { public: publicKey, secret: privateKey };
}

async function main(): Promise<void> {
    const onePair = async (label: string, pair: CryptoKeyPair): Promise<void> => {
        const keyPair: JWKKeyPair = await toJWK(pair);
        const mk: Multikey        = JWKToMultikey(keyPair);
        const mkPair: JWKKeyPair  = multikeyToJWK(mk);

        console.log(`----\n${label}:`);
        console.log("Original:")
        str(keyPair);
        console.log("Generated:")
        str(mkPair);

        if (label === "EDDSA") {
            console.log(`Values are equal? ${keyPair.secret?.x === mkPair.secret?.x && keyPair?.secret?.d === keyPair?.secret?.d}`)
        } else {
            console.log(`Values are equal? ${keyPair.secret?.x === mkPair.secret?.x && keyPair.secret?.y === mkPair.secret?.y && keyPair?.secret?.d === keyPair?.secret?.d}`)
        }
    }

    const eddsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await onePair("EDDSA", eddsaPair);

    const p256: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await onePair("ECDSA P-256", p256);

    const p384: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await onePair("ECDSA P-384", p384);
}

main()

