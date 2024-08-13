# multikeys

--- NOT PRODUCTION READY ---

# Multikey <-> JWK conversions

Conversion to and from [Multikey format](https://www.w3.org/TR/controller-document/#multikey) from JWK for the three EC curves that are defined for Verifiable Credentials: 
[ECDSA with P-256 and P-384](https://www.w3.org/TR/vc-di-ecdsa/#multikey) and [EDDSA](https://www.w3.org/TR/vc-di-eddsa/#multikey). This is really a proof-of-concept implementation, not sure it has a wide interest out there. But it shows that such conversion can indeed be done, which is an important feature in practice where multikey implementations are rare.

The package has been written in TypeScript for the Deno environment. A Node.js version may come.

The interface is pretty straightforward, see `index.ts` for now with a printout of the `deno doc` command below. More documentation may come.

```
function JWKToMultikey(keys: JsonWebKey): Multikey
function JWKToMultikey(keys: JWKKeyPair): MultikeyPair
  Convert JWK Key pair to Multikeys. This function decodes the JWK keys, finds out which binary key it encodes
  and converts the key to the multikey versions depending on the exact curve.
  
  Note that the code does not check (yet?) all combination of the JWK pairs and fields for possible errors, only
  those that would lead to error in this package. E.g., it does not check whether the x (and possibly y) values
  are identical in the secret and private JWK keys.
  
  Works for ecdsa (both P-384 and P-256), and eddsa.

  @param keys
  @return
      - exceptions if something is incorrect in the incoming data


Defined in file:///Users/ivan/W3C/github/VC/multikeys/index.ts:24:1

function multikeyToJWK(keys: Multikey): JsonWebKey
function multikeyToJWK(keys: MultikeyPair): JWKKeyPair
  Generic function to convert a multikey pair to JWK. This function decodes the multikey data
  into a binary buffer, checks the preambles and invokes the crypto specific converter functions 
  (depending on the preamble values) that do the final
  conversion from the binary data to JWK.
  
  Works for ecdsa (both P-384 and P-256), and eddsa.

  @param keys
  @return
      - exceptions if something is incorrect in the incoming data


interface JWKKeyPair

  public: JsonWebKey
  secret?: JsonWebKey

interface MultikeyPair
  The specification is a bit fuzzy and talks about Multikey for a pair, and for individual constituents.
  We need to differentiate those two...

  publicKeyMultibase: Multikey
  secretKeyMultibase?: Multikey


type Multikey = string
  Type for a Multikey
  
  One day this could become a string with a fixed regexp...
```
