import {
    ml_kem512,
    ml_kem768,
    ml_kem1024,
} from "@noble/post-quantum/ml-kem.js";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

import { XWing } from "@noble/post-quantum/hybrid.js";
import { generateKeyPair } from "jose";
import { signJWTwithES256 } from "./signing/ES256";
import { signJWTwithMLDSA } from "./signing/fullMlDsa";
import { signJWTwithMLDSAES256 } from "./signing/hybridSigning.js";

function b64uEncode(data: Uint8Array | String): string {
    return Buffer.from(data)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

// ---------------------------------------------------
// Key generation 
// ---------------------------------------------------

// X-Wing requires 32 bytes seed
const xWingSeed = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
]);

// ML-KEM-768 requires 64 bytes seed
const mlKemSeed = new Uint8Array([
    ...xWingSeed,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
]);

export const mlKem512Keys = ml_kem512.keygen(mlKemSeed);
export const mlKem768Keys = ml_kem768.keygen(mlKemSeed);
export const mlKem1024Keys = ml_kem1024.keygen(mlKemSeed);
export const xwingKeys = XWing.keygen(xWingSeed);

// Signing key pairs don't need to be exported, just generate them here
const ml_dsa44Keys = await ml_dsa44.keygen();
const ml_dsa65Keys = await ml_dsa65.keygen();
const ml_dsa87Keys = await ml_dsa87.keygen();

// Generate RSA-OAEP-256 key pair for JWE
export const rsaKeys = await generateKeyPair(
    "RSA-OAEP-256",
    {
        extractable: true,
        modulusLength: 2048,
    },
);

const es256Keys = await generateKeyPair("ES256", {
    extractable: true,
});


// ---------------------------------------------------
// Example JWT Payloads
// ---------------------------------------------------

export async function generateSignaturePayloads(payload_size: number) {

    // minimum payload size is 232 (base64 encoded) when payload_size = 1
    if (payload_size < 232) {
        throw new Error("Payload size too small, must be at least 232");
    }
    const additional_size = payload_size - 231;
    const randomString = (n: number) => Math.random().toString(36).slice(2, 2 + n);

    const payload = {
        aud: "https://oidc.integration.account.gov.uk/token",
        iss: "229pcVGuHP1lXX37T7Wfbr5SIgm",
        sub: "229pcVGuHP1lXX37T7Wfbr5SIgm",
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: randomString(additional_size),
        iat: Math.floor(Date.now() / 1000),
    };


    const b64payload = b64uEncode(JSON.stringify(payload));

    const es256JWS = await signJWTwithES256(payload, es256Keys.privateKey);
    const mlDsa44JwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-44", typ: "JWT" }));
    const mlDsa44JWS = await signJWTwithMLDSA(`${mlDsa44JwsHeader}.${payload}`, ml_dsa44Keys.secretKey, "ML-DSA-44");
    const mlDsa65JwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-65", typ: "JWT" }));
    const mlDsa65JWS = await signJWTwithMLDSA(`${mlDsa65JwsHeader}.${payload}`, ml_dsa65Keys.secretKey, "ML-DSA-65");
    const mlDsa87JwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-87", typ: "JWT" }));
    const mlDsa87JWS = await signJWTwithMLDSA(`${mlDsa87JwsHeader}.${payload}`, ml_dsa87Keys.secretKey, "ML-DSA-87");
    const hybridJwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-65-ES256", typ: "JWT" }));
    const hybridJWS = await signJWTwithMLDSAES256(
        payload,
        hybridJwsHeader,
        ml_dsa65Keys.secretKey,
        es256Keys.privateKey,
        "ML-DSA-65",
    );
    return {
        es256JWS,
        mlDsa44JWS,
        mlDsa65JWS,
        mlDsa87JWS,
        hybridJWS
    };
}

const tokenRequest = {
    aud: "https://oidc.integration.account.gov.uk/token",
    iss: "229pcVGuHP1lXX37T7Wfbr5SIgm",
    sub: "229pcVGuHP1lXX37T7Wfbr5SIgm",
    exp: Math.floor(Date.now() / 1000) + 3600, // expires in 1 hour
    jti: "RANDOM_VALUE_JTI",
    iat: Math.floor(Date.now() / 1000),
};

const b64tokenRequest = b64uEncode(JSON.stringify(tokenRequest));

export const es256JWS = await signJWTwithES256(tokenRequest, es256Keys.privateKey);
const mlDsa44JwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-44", typ: "JWT" }));
export const mlDsa44JWS = await signJWTwithMLDSA(`${mlDsa44JwsHeader}.${b64tokenRequest}`, ml_dsa44Keys.secretKey, "ML-DSA-44");
const mlDsa65JwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-65", typ: "JWT" }));
export const mlDsa65JWS = await signJWTwithMLDSA(`${mlDsa65JwsHeader}.${b64tokenRequest}`, ml_dsa65Keys.secretKey, "ML-DSA-65");
const mlDsa87JwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-87", typ: "JWT" }));
export const mlDsa87JWS = await signJWTwithMLDSA(`${mlDsa87JwsHeader}.${b64tokenRequest}`, ml_dsa87Keys.secretKey, "ML-DSA-87");
const hybridJwsHeader = b64uEncode(JSON.stringify({ alg: "ML-DSA-65-ES256", typ: "JWT" }));
export const hybridJWS = await signJWTwithMLDSAES256(
    tokenRequest,
    hybridJwsHeader,
    ml_dsa65Keys.secretKey,
    es256Keys.privateKey,
    "ML-DSA-65",
);