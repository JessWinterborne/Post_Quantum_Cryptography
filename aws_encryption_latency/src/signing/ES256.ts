import { JWTPayload, SignJWT, jwtVerify } from "jose";

export async function signJWTwithES256(
    payload: JWTPayload,
    secretKey: CryptoKey,
) {
    const JWS = await new SignJWT(payload)
        .setProtectedHeader({ alg: "ES256", typ: "JWT" })
        .sign(secretKey);

    return JWS;
}

export async function verifyJWTwithES256(
    JWS: string | Uint8Array<ArrayBufferLike>,
    publicKey: CryptoKey,
) {
    try {
        const { payload, protectedHeader } = await jwtVerify(JWS, publicKey);
        console.log("Verified header:", protectedHeader);
        console.log("Verified payload:", payload);
        return { payload, protectedHeader };
    } catch (err) {
        console.log("Error while verifying JWS", err);
        throw new Error();
    }
}
