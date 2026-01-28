import {
    KMSClient,
    SignCommand,
    VerifyCommand,
    GetPublicKeyCommand,
    SigningAlgorithmSpec
} from "@aws-sdk/client-kms";
import { randomUUID, sign } from "crypto";
import { performance } from "perf_hooks";

type LatencyVsPayloadSizeResult = Record<string, { signMs: number[]; verifyMs: number[] }>;
type TotalLatencyVsPayloadSizeResult = {
    keyId: string;
    signingAlgorithm: string;
    results: LatencyVsPayloadSizeResult;
}[];

const kms = new KMSClient({});

function utf8Bytes(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

async function latenciesVsPayloadSize(keyId: string, iterations: number, signingAlgorithm: SigningAlgorithmSpec) {
    // Fetch once (optional, but helps avoid per-iteration extra work)
    await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));

    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    const results: LatencyVsPayloadSizeResult = {};

    // Generate payloads of increasing size
    for (let len = 200; len <= 2200; len += 200) {
        let messagePayload = "";
        for (let i = 0; i < len; i++) {
            messagePayload += chars[Math.floor(Math.random() * chars.length)];
        }
        console.log(`KeyId: ${keyId}, Len: ${len}`);

        const useParallel = process.env.USE_PARALLEL === "true" || false;
        if (useParallel) {
            // Parallel version

            // Pre-warm KMS client for this payload size
            for (let i = 0; i < 20; i++) {
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
            }

            // Additional pre-warming to stabilise performance
            const testPromises = Array.from({ length: 50 }, async (_, i) => {
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }
            });
            await Promise.all(testPromises);

            // Run actual measurements in parallel
            const promises = Array.from({ length: iterations }, async (_, i) => {

                const s0 = performance.now();
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const s1 = performance.now();

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const v0 = performance.now();
                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const v1 = performance.now();

                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }

                return {
                    signMs: s1 - s0,
                    verifyMs: v1 - v0
                };
            });

            const iterationResults = await Promise.all(promises);
            const signMs = iterationResults.map(r => r.signMs);
            const verifyMs = iterationResults.map(r => r.verifyMs);
            results[len.toString()] = { signMs: signMs, verifyMs: verifyMs };

        } else {

            // For each payload size, run iterations
            const signMs: number[] = [];
            const verifyMs: number[] = [];

            // Pre-warm KMS client for this payload size
            for (let i = 0; i < 20; i++) {
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
            }

            for (let i = 0; i < iterations; i++) {

                const s0 = performance.now();
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const s1 = performance.now();

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const v0 = performance.now();
                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: utf8Bytes(messagePayload),
                        MessageType: "RAW",
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const v1 = performance.now();


                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }

                signMs.push(s1 - s0);
                verifyMs.push(v1 - v0);
            }
            results[len.toString()] = { signMs: signMs, verifyMs: verifyMs };
        }

    }
    return results
}

// Lambda handler
export const handler = async (event: any) => {
    const mlDsa44Arn = process.env.ML_DSA_44_ARN;
    const mlDsa65Arn = process.env.ML_DSA_65_ARN;
    const mlDsa87Arn = process.env.ML_DSA_87_ARN;
    const eccP256Arn = process.env.ECC_NIST_P256_ARN;

    const keyAlgMap: Record<string, SigningAlgorithmSpec> = {};

    if (mlDsa44Arn) keyAlgMap[mlDsa44Arn] = SigningAlgorithmSpec.ML_DSA_SHAKE_256;
    if (mlDsa65Arn) keyAlgMap[mlDsa65Arn] = SigningAlgorithmSpec.ML_DSA_SHAKE_256;
    if (mlDsa87Arn) keyAlgMap[mlDsa87Arn] = SigningAlgorithmSpec.ML_DSA_SHAKE_256;
    if (eccP256Arn) keyAlgMap[eccP256Arn] = SigningAlgorithmSpec.ECDSA_SHA_256;

    const entries = Object.entries(keyAlgMap);
    const iterations = Number(event?.iterations ?? process.env.ITERATIONS ?? "100");

    // Warm-up each key once to reduce cold-start variability
    for (const [keyId, signingAlgorithm] of entries) {
        const msg = utf8Bytes(
            JSON.stringify({ now: Date.now(), nonce: randomUUID(), warmup: true })
        );

        await kms.send(
            new SignCommand({
                KeyId: keyId,
                Message: msg,
                MessageType: "RAW",
                SigningAlgorithm: signingAlgorithm,
            })
        );
    }

    const results: TotalLatencyVsPayloadSizeResult = [];
    for (const [keyId, signingAlgorithm] of entries) {
        // for (const [keyId, signingAlgorithm] of entries.reverse()) {
        const singleKeyResults = await latenciesVsPayloadSize(keyId, iterations, signingAlgorithm);
        results.push({
            keyId,
            signingAlgorithm,
            results: singleKeyResults
        });
    }

    return {
        iterations,
        results
    };
};
