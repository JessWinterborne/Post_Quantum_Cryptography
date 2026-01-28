import { CompactEncrypt, compactDecrypt } from "jose";

export async function encryptSignedJwtWithRSAOAEP(
    jws: string,
    rsaPub: Uint8Array<ArrayBufferLike> | CryptoKey,
) {
    const jwe = await new CompactEncrypt(new TextEncoder().encode(jws))
        .setProtectedHeader({
            alg: "RSA-OAEP-256",
            enc: "A256GCM",
        })
        .encrypt(rsaPub);

    return jwe;
}

export async function decryptSignedJwtWithRSAOAEP(
    jwe: string,
    rsaPriv: Uint8Array<ArrayBufferLike> | CryptoKey,
) {
    const { plaintext } = await compactDecrypt(jwe, rsaPriv);
    const decryptedJWS = new TextDecoder().decode(plaintext);
    return decryptedJWS;
}
