import { 
    JWKKeyPair, Multikey,
    cryptoToMultikey, multikeyToCrypto
} from "../index";

/** ----------------------------- */

/************* Debugging help ***********/
// deno-lint-ignore no-explicit-any
export function str(inp: any): void {
    console.log(JSON.stringify(inp, null, 4));
}

/**
 * Convert a CryptoKey Pair into a JWK Pair.
 * @param newPair 
 * @returns 
 */

async function toJWK(newPair: CryptoKeyPair): Promise<JWKKeyPair> {
    const publicKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.publicKey);
    const privateKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
    return { publicKey: publicKey, privateKey: privateKey };
}

/**
 * Test: Convert fresh CryptoKeys pairs into Multikey pairs and back; the crypto values should be identical.
 */
async function main(): Promise<void> {
    const onePair = async (label: string, pair: CryptoKeyPair): Promise<void> => {
        // Do a round-trip
        const mk:      Multikey      = await cryptoToMultikey(pair);
        const newPair: CryptoKeyPair = await multikeyToCrypto(mk);

        // For debugging, both keypairs are converted into JWK
        const keyPair = await toJWK(pair);
        const mkPair  = await toJWK(newPair);

        console.log(`----\n${label}:`);
        console.log(`Original key in JWK:`)
        str(keyPair);
        console.log(`Generated key in JWK:`)
        str(mkPair);

        if (label === "EDDSA") {
            console.log(`Values are equal? ${keyPair.privateKey?.x === mkPair.privateKey?.x && keyPair?.privateKey?.d === keyPair?.privateKey?.d}`)
        } else {
            console.log(`Values are equal? ${keyPair.privateKey?.x === mkPair.privateKey?.x && keyPair.privateKey?.y === mkPair.privateKey?.y && keyPair?.privateKey?.d === keyPair?.privateKey?.d}`)
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

