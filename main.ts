import * as utils from './lib/utils.ts';
import { JWKKeyPair, MultikeyPair } from "./lib/common.ts";


/** ----------------------------- */

/************* Debugging help ***********/
// deno-lint-ignore no-explicit-any
export function str(inp: any): void {
    console.log(JSON.stringify(inp, null, 4));
}


// generate an eddsa key
const newPair: CryptoKeyPair = await crypto.subtle.generateKey({name: "Ed25519"}, true, ["sign", "verify"]) as CryptoKeyPair;
const keyPair: JWKKeyPair = await utils.toJWK(newPair);


const mk: MultikeyPair   = utils.JWKToMultikey(keyPair);
const mkPair: JWKKeyPair = utils.MultikeyToJWK(mk);

str(keyPair);
str(mkPair);

console.log(`Values are equal? ${keyPair.secret?.x === mkPair.secret?.x && keyPair?.secret?.d === keyPair?.secret?.d}`)

