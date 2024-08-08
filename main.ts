import { JWKKeyPair, MultikeyPair, JWKToMultikey, MultikeyToJWK } from "./index.ts";

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


// generate an eddsa key
// const newPair: CryptoKeyPair = await crypto.subtle.generateKey({name: "Ed25519"}, true, ["sign", "verify"]) as CryptoKeyPair;
const newPair: CryptoKeyPair = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign", "verify"]) as CryptoKeyPair;
const keyPair: JWKKeyPair = await toJWK(newPair);


const mk: MultikeyPair   = JWKToMultikey(keyPair);
const mkPair: JWKKeyPair = MultikeyToJWK(mk);

str(keyPair);
str(mkPair);

console.log(`Values are equal? ${keyPair.secret?.x === mkPair.secret?.x && keyPair?.secret?.d === keyPair?.secret?.d}`)

