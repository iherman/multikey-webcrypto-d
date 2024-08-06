import * as eddsa from "./eddsa.ts";
import * as ecdsa from "./ecdsa.ts";


export interface JWKKeyPair {
    public: JsonWebKey;
    secret?: JsonWebKey;
}

export type Multikey = string;

export interface MultikeyPair {
    publicKeyMultibase: Multikey;
    secretKeyMultibase?: Multikey;
}

export interface MultikeyPairBinary {
    public: Uint8Array;
    secret?: Uint8Array
}

export type Preamble<T> = [T,T];

interface MultikeyPreambles {
    public:  Preamble<number>,
    secret: Preamble<number>,
}

export const EddsaPreambles: MultikeyPreambles = {
    public:  [0xed, 0x01],
    secret: [0x80, 0x26],
};

export const Ecdsa256Preambles: MultikeyPreambles = {
    public:  [0x80, 0x24],
    secret: [0x86, 0x26],
}

export const Ecdsa384Preambles: MultikeyPreambles = {
    public:  [0x81, 0x24],
    secret: [0x87, 0x26],
};

export enum CryptoKeyClasses {
    ECDSA_384 = "ecdsa 384",
    ECDSA_256 = "ecdsa 256",
    EDDSA     = "eddsa"
}

export enum CryptoKeyTypes {
    PUBLIC  = "public",
    PRIVATE = "private"
}

export interface CryptoKeyData {
    crClass : CryptoKeyClasses,
    crType  : CryptoKeyTypes,
}

export type ClassToPreamble = {
    [key in CryptoKeyClasses]: MultikeyPreambles;
};

export type ClassToDecoder = {
    [key in CryptoKeyClasses]: (key_class: CryptoKeyClasses, x: Uint8Array, d?: Uint8Array) => JWKKeyPair;
}

export type ClassToEncoder = {
    [key in CryptoKeyClasses]: (x: Uint8Array, d: Uint8Array | undefined, _y?: Uint8Array) => MultikeyPairBinary
}

/**
 * Mapping to the preambles that must be added to the encoded crypto data
 */
export const classToPreamble: ClassToPreamble = {
    [CryptoKeyClasses.EDDSA]: EddsaPreambles,
    [CryptoKeyClasses.ECDSA_256]: Ecdsa256Preambles,
    [CryptoKeyClasses.ECDSA_384]: Ecdsa384Preambles,
};

/**
 * Mapping to decoder, ie, decoding the Multicode values to JWK
 */
export const classToDecoder: ClassToDecoder = {
    [CryptoKeyClasses.EDDSA]: eddsa.convertCryptoToJWK,
    [CryptoKeyClasses.ECDSA_256]: ecdsa.convertCryptoToJWK,
    [CryptoKeyClasses.ECDSA_384]: ecdsa.convertCryptoToJWK,
};

/**
 * Mapping to encoders, ie, encoding the JWK values to Multicode
 */
export const classToEncoder: ClassToEncoder = {
    [CryptoKeyClasses.EDDSA]: eddsa.convertJWKCryptoValues,
    [CryptoKeyClasses.ECDSA_256]: ecdsa.convertJWKCryptoValues,
    [CryptoKeyClasses.ECDSA_384]: ecdsa.convertJWKCryptoValues,
};
