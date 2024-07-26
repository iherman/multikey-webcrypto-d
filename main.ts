import * as utils from './lib/utils.ts';
import * as eddsa from './lib/eddsa.ts';
import { JWKKeyPair, MultikeyPair } from "./lib/types.ts";


/** ----------------------------- */

/************* Debugging help ***********/
// deno-lint-ignore no-explicit-any
export function str(inp: any): void {
    console.log(JSON.stringify(inp, null, 4));
}


async function toJWK(newPair: CryptoKeyPair): Promise<JWKKeyPair> {
    const publicKey: JsonWebKey  = await crypto.subtle.exportKey("jwk", newPair.publicKey);
    const privateKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
    return { public: publicKey, private: privateKey };
}


// generate an eddsa key
const newPair: CryptoKeyPair = await crypto.subtle.generateKey({name: "Ed25519"}, true, ["sign", "verify"]) as CryptoKeyPair;
const keyPair: JWKKeyPair = await toJWK(newPair);


const mk: MultikeyPair   = eddsa.JWKToMultikey(keyPair.public, keyPair.private);
const mkPair: JWKKeyPair = utils.MultikeyPairToJWK(mk);

str(keyPair);
str(mkPair);

console.log(`Values are equal? ${keyPair.private?.x === mkPair.private?.x && keyPair?.private?.d === keyPair?.private?.d}`)

