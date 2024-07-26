export interface JWKKeyPair {
    public: JsonWebKey;
    private?: JsonWebKey;
}

export type Multikey = string;

export interface MultikeyPair {
    publicKeyMultibase: Multikey;
    secretKeyMultibase?: Multikey;
}

export type Preamble<T> = [T,T];

interface MultikeyPreambles {
    public:  Preamble<number>,
    private: Preamble<number>,
}

export const EddsaPreambles: MultikeyPreambles = {
    public:  [0xed, 0x01],
    private: [0x80, 0x26],
};

export const Ecdsa256Preambles: MultikeyPreambles = {
    public:  [0x80, 0x24],
    private: [0x86, 0x26],
}

export const Ecdsa384Preambles: MultikeyPreambles = {
    public:  [0x81, 0x24],
    private: [0x87, 0x26],
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

