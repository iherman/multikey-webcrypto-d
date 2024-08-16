
All tests are roundtrips: a multikey format of a key is generated, and that is converted into JWK or CryptoKey. The results are printed on the screen and a rudimentary test is also done comparing curve values in JWK. All tests repeat the same cycle for EDDSA, ECDSA+P256 and ECDSA+P384.

- `roundtrip_jwk`: roundtrip with full JWK pairs (i.e., public and secret keys)
- `roundtrip_s_jwk`: roundtrip with single public JWK
- `roundtrip_cry`: roundtrip with full CryptoKey Pairs pairs (i.e., public and secret keys)
- `roundtrip_s_cry`: roundtrip with single public CryptoKey
