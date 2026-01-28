import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

// ---------------------------------------------------
// ---------------------------------------------------
// Util Functions for conversions and encoding
// ---------------------------------------------------
// ---------------------------------------------------
export function b64uEncode(data: Uint8Array | String): string {
    return Buffer.from(data)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}


// ---------------------------------------------------
// ---------------------------------------------------
// ML-DSA Signing and Verification Functions
// ---------------------------------------------------
// ---------------------------------------------------

export async function signJWTwithMLDSA(
    b64Payload: string,
    secretKey: Uint8Array<ArrayBufferLike>,
    algo: "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87",
): Promise<string> {
    // Sign encoded payload
    let signature: Uint8Array;
    if (algo === "ML-DSA-44") {
        signature = await ml_dsa44.sign(Buffer.from(b64Payload), secretKey);
    } else if (algo === "ML-DSA-65") {
        signature = await ml_dsa65.sign(Buffer.from(b64Payload), secretKey);
    } else if (algo === "ML-DSA-87") {
        signature = await ml_dsa87.sign(Buffer.from(b64Payload), secretKey);
    } else {
        throw new Error("Unsupported algorithm size");
    }

    // Encode signature
    const encodedSignature = b64uEncode(signature);

    // Combine into JWS token
    const token = `${b64Payload}.${encodedSignature}`;
    return token;
}

export async function verifyJWTwithMLDSA(
    b64Jws: string,
    publicKey: Uint8Array,
    algo: "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87",
): Promise<boolean> {
    // Split header, payload, signature
    const parts = b64Jws.split(".");
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
