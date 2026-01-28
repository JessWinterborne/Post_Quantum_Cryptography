import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { signJWTwithES256 } from "./ES256.js";

// ---------------------------------------------------
// ---------------------------------------------------
// Utils
// ---------------------------------------------------
// ---------------------------------------------------

export function b64uEncode(data: Uint8Array | String): string {
    return Buffer.from(data)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

export function b64uDecode(s: string): Uint8Array {
    const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
    return new Uint8Array(Buffer.from(b64, "base64"));
}


// ---------------------------------------------------
// ---------------------------------------------------
// ML-DSA + ES256 Hybrid Signing and Verification 
// ---------------------------------------------------
// ---------------------------------------------------

export async function signJWTwithMLDSAES256(
    payload: object,
    headerb64: string,
    mlDsaSecretKey: Uint8Array<ArrayBufferLike>,
    es256SecretKey: CryptoKey,
    mlDsaAlgo: "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87",
): Promise<string> {
    // Encode payload
    // const encodedPayload = b64uEncode(JSON.stringify(payload));

    const JWS = await signJWTwithES256(
        payload as unknown as Record<string, unknown>,
        es256SecretKey,
    );

    const es256Signatureb64 = JWS.split(".")[2];

    const mlDsaSigningPayload = `${headerb64}.${b64uEncode(JSON.stringify(payload))}`;

    // Sign encoded payload
    let signature: Uint8Array;
    if (mlDsaAlgo === "ML-DSA-44") {
        signature = await ml_dsa44.sign(
            Buffer.from(mlDsaSigningPayload),
            mlDsaSecretKey,
        );
    } else if (mlDsaAlgo === "ML-DSA-65") {
        signature = await ml_dsa65.sign(
            Buffer.from(mlDsaSigningPayload),
            mlDsaSecretKey,
        );
    } else if (mlDsaAlgo === "ML-DSA-87") {
        signature = await ml_dsa87.sign(
            Buffer.from(mlDsaSigningPayload),
            mlDsaSecretKey,
        );
    } else {
        throw new Error("Unsupported algorithm size");
    }

    // Encode signature
    const encodedMlDsaSignature = b64uEncode(signature);

    const combinedSignature = b64uEncode(
        JSON.stringify({
            t: es256Signatureb64,
            pq: encodedMlDsaSignature,
        }),
    );

    // Combine into JWS token
    const token = `${mlDsaSigningPayload}.${combinedSignature}`;
    return token;
}

export async function verifyJWTwithMLDSAES256(
    token: string,
    publicKey: Uint8Array,
    algo: "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87",
): Promise<boolean> {
    // Split header, payload, signature
    const parts = token.split(".");
    if (parts.length !== 3) {
        throw new Error("Invalid token format, expected header.payload.signature");
    }
    const [encodedHeader, encodedPayload, sigB64] = parts;

    // Reconstruct signing input (header.payload)
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Decode signature (assuming standard base64)
    const signature = Buffer.from(sigB64, "base64");

    // Verify signature
    let isValid: boolean;
    if (algo === "ML-DSA-44") {
        isValid = await ml_dsa44.verify(
            signature,
            Buffer.from(signingInput),
            publicKey,
        );
    } else if (algo === "ML-DSA-65") {
        isValid = await ml_dsa65.verify(
            signature,
            Buffer.from(signingInput),
            publicKey,
        );
    } else if (algo === "ML-DSA-87") {
        isValid = await ml_dsa87.verify(
            signature,
            Buffer.from(signingInput),
            publicKey,
        );
    } else {
        throw new Error("Unsupported algorithm size");
    }
    return isValid;
}
