import { Multibase, JWKToMultikey, multikeyToJWK } from "../index";

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

async function main(): Promise<void> {
    const onePair = async (label: string, key: CryptoKey): Promise<void> => {
        const key_jwk: JsonWebKey = await crypto.subtle.exportKey("jwk", key);
        const mk: Multibase       = JWKToMultikey(key_jwk);
        const gen_jwk: JsonWebKey = multikeyToJWK(mk);

        console.log(`----\n${label}:`);
        console.log("Original:")
        str(key_jwk);
        console.log("Generated:")
        str(gen_jwk);

        if (label === "EDDSA") {
            console.log(`Values are equal? ${key_jwk.x === gen_jwk.x}`)
        } else {
            console.log(`Values are equal? ${key_jwk.x === gen_jwk.x && key_jwk.y === gen_jwk.y}`)
        }
    }

    const eddsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await onePair("EDDSA", eddsaPair.publicKey);

    const p256: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await onePair("ECDSA P-256", p256.publicKey);

    const p384: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await onePair("ECDSA P-384", p384.publicKey);
}

main()

