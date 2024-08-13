# multikeys

--- NOT PRODUCTION READY ---

# Multikey <-> JWK conversions

Conversion to and from [Multikey format](https://www.w3.org/TR/controller-document/#multikey) from JWK for the three EC curves that are defined for Verifiable Credentials: 
[ECDSA with P-256 and P-384](https://www.w3.org/TR/vc-di-ecdsa/#multikey) and [EDDSA](https://www.w3.org/TR/vc-di-eddsa/#multikey). This is really a proof-of-concept implementation, not sure it has a wide interest out there. But it shows that such conversion can indeed be done, which is an important feature in practice where multikey implementations are rare.

The package has been written in TypeScript for the Deno environment. A Node.js version may come.

The interface is pretty straightforward, see `index.ts` for now. More documentation may be coming.
