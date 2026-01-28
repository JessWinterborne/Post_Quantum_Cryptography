import {
    KMSClient,
    GetPublicKeyCommand
} from "@aws-sdk/client-kms";
import { performance } from "perf_hooks";
// import { es256JWS, mlDsa44JWS, mlDsa65JWS, mlDsa87JWS, hybridJWS, rsaKeys, mlKem512Keys, mlKem768Keys, mlKem1024Keys, xwingKeys } from "./payloads.js";
import { generateSignaturePayloads, rsaKeys, mlKem512Keys, mlKem768Keys, mlKem1024Keys, xwingKeys } from "./payloads.js";

import { encryptSignedJwtWithRSAOAEP, decryptSignedJwtWithRSAOAEP } from "./encryption/rsaLocal.js";
import { encryptJwtRsa, decryptJwtRsa } from "./encryption/rsaKms.js";
import { encryptSignedJwtDirectMlKem, decryptSignedJwtDirectMlKem } from "./encryption/fullMlKemExample.js";

type latencyMeasurements = {
    algorithm: string;
    encryptionTimesMs: number[];
    decryptionTimesMs: number[];
}

import { createPublicKey } from "node:crypto";

type JWK = {
    kty: string;
    n?: string;
    e?: string;
    crv?: string;
    kid?: string;
    use?: "sig" | "enc";
    alg?: "RSA-OAEP-256";
    customPub?: string | Uint8Array<ArrayBufferLike>; // For AKP (ML-KEM)
    customPriv?: string | Uint8Array<ArrayBufferLike>; // For AKP (ML-KEM) private key
}

type JWKS = JWK[];

const kms = new KMSClient({});

async function getPublicKeyFromKms(kmsKeyId: string): Promise<JWKS> {
    console.log(`Fetching public key from KMS for KeyId: ${kmsKeyId}`);

    // Fetch public key from KMS
    console.log("Sending GetPublicKeyCommand to KMS");
    const resp = await kms.send(new GetPublicKeyCommand({ KeyId: kmsKeyId }));
    console.log("Received public key from KMS");

    if (!resp.PublicKey) throw new Error("KMS returned no PublicKey");

    // KMS returns SubjectPublicKeyInfo (SPKI) DER bytes
    const keyObj = createPublicKey({
        key: Buffer.from(resp.PublicKey),
        format: "der",
        type: "spki",
    });
    console.log("Created public key object from KMS response");

    // Node will produce { kty, n, e } for RSA
    const jwk = keyObj.export({ format: "jwk" }) as JWK;
    console.log("Converted public key to JWK:", jwk);

    jwk.kid = kmsKeyId;
    jwk.alg = "RSA-OAEP-256";
    jwk.use = "enc";

    return [jwk];
}

async function runForPayloadSize(payload_size: number, event: any, RSA_2048_ARN: string = process.env.RSA_2048_ARN as string) {
    const { es256JWS, mlDsa44JWS, mlDsa65JWS, mlDsa87JWS, hybridJWS } = await generateSignaturePayloads(payload_size);
    const iterations = Number(event?.iterations ?? process.env.ITERATIONS ?? "100");

    // Test RSA-OAEP-256 Local Encryption Latency
    console.log("Testing RSA-OAEP-256 Local Encryption Latency");
    const rsaLocalEncryptionMeasurements: latencyMeasurements = {
        algorithm: "RSA-OAEP-256 Local",
        encryptionTimesMs: [],
        decryptionTimesMs: []
    };

    for (let i = 0; i < iterations; i++) {
        const startEncrypt = performance.now();
        const encryptedJwt = await encryptSignedJwtWithRSAOAEP(es256JWS, rsaKeys.publicKey);
        const endEncrypt = performance.now();
        rsaLocalEncryptionMeasurements.encryptionTimesMs.push(endEncrypt - startEncrypt);
        const startDecrypt = performance.now();
        const decryptedJwt = await decryptSignedJwtWithRSAOAEP(encryptedJwt, rsaKeys.privateKey);
        const endDecrypt = performance.now();
        rsaLocalEncryptionMeasurements.decryptionTimesMs.push(endDecrypt - startDecrypt);

        // Optional: Verify decrypted JWT matches original
        if (decryptedJwt !== es256JWS) {
            throw new Error(`Decrypted JWT does not match original, decrypted: ${decryptedJwt}, original: ${es256JWS}`);
        }

    }

    // Test RSA-OAEP-256 KMS Encryption Latency
    console.log("Testing RSA-OAEP-256 KMS Encryption Latency");
    const rsaJwks = await getPublicKeyFromKms(RSA_2048_ARN);
    await encryptJwtRsa(es256JWS, rsaJwks); // Warm up
    const rsaKmsEncryptionMeasurements: latencyMeasurements = {
        algorithm: "RSA-OAEP-256 KMS",
        encryptionTimesMs: [],
        decryptionTimesMs: []
    };

    for (let i = 0; i < iterations; i++) {
        const startEncrypt = performance.now();
        const encryptedJwt = await encryptJwtRsa(es256JWS, rsaJwks);
        const endEncrypt = performance.now();
        rsaKmsEncryptionMeasurements.encryptionTimesMs.push(endEncrypt - startEncrypt);
        const startDecrypt = performance.now();
        const decryptedJwt = await decryptJwtRsa(encryptedJwt, RSA_2048_ARN);
        const endDecrypt = performance.now();
        rsaKmsEncryptionMeasurements.decryptionTimesMs.push(endDecrypt - startDecrypt);

        // Optional: Verify decrypted JWT matches original
        if (decryptedJwt !== es256JWS) {
            throw new Error(`Decrypted JWT does not match original, decrypted: ${decryptedJwt}, original: ${es256JWS}`);
        }

    }

    // Test ML-KEM Encryption Latency
    console.log("Testing ML-KEM-512 Encryption Latency");
    const algKeySet = {
        "ML-KEM-512": { keys: mlKem512Keys, jws: mlDsa44JWS },
        "ML-KEM-768": { keys: mlKem768Keys, jws: mlDsa65JWS },
        "ML-KEM-1024": { keys: mlKem1024Keys, jws: mlDsa87JWS },
        "X-Wing": { keys: xwingKeys, jws: hybridJWS }
    }
    const mlKemEncryptionMeasurementsArray: latencyMeasurements[] = [];
    for (const [alg, { keys, jws }] of Object.entries(algKeySet)) {
        console.log(`Testing ${alg} Encryption Latency`);
        const mlKemEncryptionMeasurements: latencyMeasurements = {
            algorithm: alg,
            encryptionTimesMs: [],
            decryptionTimesMs: []
        };

        for (let i = 0; i < iterations; i++) {
            const startEncrypt = performance.now();
            const encryptedJwt = await encryptSignedJwtDirectMlKem(jws, keys.publicKey as Uint8Array<ArrayBuffer>, alg as "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" | "X-Wing");
            const endEncrypt = performance.now();
            mlKemEncryptionMeasurements.encryptionTimesMs.push(endEncrypt - startEncrypt);
            const startDecrypt = performance.now();
            const decryptedJwt = await decryptSignedJwtDirectMlKem(encryptedJwt, keys.secretKey as Uint8Array<ArrayBuffer>);
            const endDecrypt = performance.now();
            mlKemEncryptionMeasurements.decryptionTimesMs.push(endDecrypt - startDecrypt);

            // Optional: Verify decrypted JWT matches original
            if (decryptedJwt !== jws) {
                throw new Error(`Decrypted JWT does not match original, decrypted: ${decryptedJwt}, original: ${jws}`);
            }

        }
        mlKemEncryptionMeasurementsArray.push(mlKemEncryptionMeasurements);
    }

    const results = [
        rsaLocalEncryptionMeasurements,
        rsaKmsEncryptionMeasurements,
        ...mlKemEncryptionMeasurementsArray
    ];
    return {
        iterations,
        results
    };

}

// Lambda handler
export const handler = async (event: any) => {
    const RSA_2048_ARN = process.env.RSA_2048_ARN;
    if (!RSA_2048_ARN) {
        throw new Error("RSA_2048_ARN environment variable not set");
    }

    const runSizeIterations = process.env.RUN_SIZE_ITERATIONS?.toLowerCase() === "true" || false;

    if (runSizeIterations) {
        const payloadSizes = [250, 500, 1000, 2000, 4000]; // in bytes
        const allResults = [];

        for (const size of payloadSizes) {
            console.log(`Running tests for payload size: ${size} bytes`);
            const result = await runForPayloadSize(size, event, RSA_2048_ARN);
            allResults.push({
                payloadSize: size,
                ...result
            });
        }

        console.log("All tests completed");
        return {
            allResults
        };
    } else {
        console.log("Running tests for single payload size of 250 bytes");
        const result = await runForPayloadSize(250, event);
        console.log("Tests completed for single payload size");
        return result;
    }
};
