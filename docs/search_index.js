(function () {
  window.DENO_DOC_SEARCH_INDEX = {"nodes":[{"kind":[{"char":"I","kind":"Interface","title":"Interface"}],"name":"JWKKeyPair","file":".","doc":"Public/secret pair of JWK instances","url":"././~/JWKKeyPair.html","deprecated":false},{"kind":[{"char":"p","kind":"Property","title":"Property"}],"name":"JWKKeyPair.publicKey","file":".","doc":"","url":"././~/JWKKeyPair.publicKey.html","deprecated":false},{"kind":[{"char":"p","kind":"Property","title":"Property"}],"name":"JWKKeyPair.privateKey","file":".","doc":"","url":"././~/JWKKeyPair.privateKey.html","deprecated":false},{"kind":[{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"}],"name":"JWKToMultikey","file":".","doc":"Convert a JWK Key pair to Multikeys. This function decodes the JWK keys, finds out which binary key it encodes\nand, converts the key to the multikey versions depending on the exact curve.\n\nNote that the code does not check (yet?) all combination of JWK pairs and fields for possible errors, only\nthose that would lead to error in this package. E.g., it does not check whether the x (and possibly y) values\nare identical in the secret and private JWK keys.\n\nWorks for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.\n","url":"././~/JWKToMultikey.html","deprecated":false},{"kind":[{"char":"T","kind":"TypeAlias","title":"Type Alias"}],"name":"Multibase","file":".","doc":"Type for a Multibase\n\nOne day this could become a string with a fixed regexp...","url":"././~/Multibase.html","deprecated":false},{"kind":[{"char":"I","kind":"Interface","title":"Interface"}],"name":"Multikey","file":".","doc":"Pair of keys in Multibase encoding. Using the field names as defined in the \n[Multikey specification](https://www.w3.org/TR/controller-document/#multikey).","url":"././~/Multikey.html","deprecated":false},{"kind":[{"char":"p","kind":"Property","title":"Property"}],"name":"Multikey.publicKeyMultibase","file":".","doc":"","url":"././~/Multikey.publicKeyMultibase.html","deprecated":false},{"kind":[{"char":"p","kind":"Property","title":"Property"}],"name":"Multikey.secretKeyMultibase","file":".","doc":"","url":"././~/Multikey.secretKeyMultibase.html","deprecated":false},{"kind":[{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"}],"name":"cryptoToMultikey","file":".","doc":"Convert a Crypto Key pair to Multikeys. This function exports the cryptokeys into a JWK Key pair,\nand uses the `JWKToMultikey` function.\n\nWorks for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.\n\nNote that, because WebCrypto methods are asynchronous, so is this function.\n","url":"././~/cryptoToMultikey.html","deprecated":false},{"kind":[{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"}],"name":"multikeyToCrypto","file":".","doc":"Convert a multikey pair to Web Crypto. This function decodes the multikey data into JWK using the\n`multikeyToJWK` function, and imports the resulting keys into Web Crypto.\n\nWorks for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.\n\nNote that, because WebCrypto methods are asynchronous, so is this function.\n","url":"././~/multikeyToCrypto.html","deprecated":false},{"kind":[{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"},{"char":"f","kind":"Function","title":"Function"}],"name":"multikeyToJWK","file":".","doc":"Convert a multikey pair to JWK. This function decodes the multikey data\ninto a binary buffer, checks the preambles and invokes the crypto specific converter functions \n(depending on the preamble values) that do the final conversion from the binary data to JWK.\n\nWorks for `ecdsa` (both `P-384` and `P-256`), and `eddsa`.\n","url":"././~/multikeyToJWK.html","deprecated":false}]};
})()