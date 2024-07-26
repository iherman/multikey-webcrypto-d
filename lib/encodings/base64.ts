/*************************************************************************************************/
/*                                       Base64 Encoding                                         */
/*************************************************************************************************/

/*
 * These two came from perplexity, hopefully it is correct...
 */
const base64ToUrl = (base64String: string): string => {
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

const urlToBase64 = (base64Url: string): string => {
    return base64Url.replace(/-/g, '+').replace(/_/g, '/');
};

/**
 * Convert an array buffer to base64url value.
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param arrayBuffer 
 * @returns 
 */
export function Uint8ArrayToBase64Url(bytes: Uint8Array): string {
    let binary: string = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64String = btoa(binary);
    return base64ToUrl(base64String);
}

/**
 * Convert a base64url value to Uint8Array
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param string 
 * @returns 
 */
export function base64UrlToUint8Array(url: string): Uint8Array {
    const base64string = urlToBase64(url);

    const binary = atob(base64string);

    const byteArray = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        byteArray[i] = binary.charCodeAt(i);
    }
    return byteArray;
}

/**
 * Convert a CryptoKey Pair to a JWK Pair
 * @param newPair 
 * @returns 
 */
export async function toJWK(newPair: CryptoKeyPair): Promise<types.JWKKeyPair> {
    const publicKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.publicKey);
    const privateKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
    return { public: publicKey, private: privateKey };
}