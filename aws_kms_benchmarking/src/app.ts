import {
    KMSClient,
    SignCommand,
    VerifyCommand,
    GetPublicKeyCommand,
    SigningAlgorithmSpec,
} from "@aws-sdk/client-kms";
import { randomUUID } from "crypto";
import { performance } from "perf_hooks";

type LatencyVsConcurrencyResult = Record<
    string,
    { signMs: number[]; verifyMs: number[] }
>;
type TotalLatencyVsConcurrencyResult = {
    keyId: string;
    signingAlgorithm: string;
    results: LatencyVsConcurrencyResult;
}[];

const kms = new KMSClient({});

// ---- Hardcoded test configuration ----
const PAYLOAD_SIZE = 1200; // characters (roughly bytes for ASCII)
const CONCURRENCY_LEVELS = [10, 100, 200, 300, 400, 600, 800, 1000];
const WARMUP_ITERATIONS = 20;
const SLEEP_BETWEEN_BURSTS_MS = 1000;

function utf8Bytes(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeAsciiPayload(len: number): string {
    const chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let out = "";
    for (let i = 0; i < len; i++) {
        out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
}

async function latenciesVsConcurrency(
    keyId: string,
    iterations: number,
    signingAlgorithm: SigningAlgorithmSpec
): Promise<LatencyVsConcurrencyResult> {
    // Fetch once to avoid extra per-iteration work (and ensure key is reachable)
    await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));

    const messagePayload = makeAsciiPayload(PAYLOAD_SIZE);
    const messageBytes = utf8Bytes(messagePayload);

    // Warm up (sequential) to reduce cold variability for this key/payload
    for (let i = 0; i < WARMUP_ITERATIONS; i++) {
        const signResp = await kms.send(
            new SignCommand({
                KeyId: keyId,
                Message: messageBytes,
                MessageType: "RAW",
                SigningAlgorithm: signingAlgorithm,
            })
        );

        const signature = signResp.Signature;
        if (!signature) throw new Error(`KMS Sign returned no Signature for ${keyId}`);

        const verifyResp = await kms.send(
            new VerifyCommand({
                KeyId: keyId,
                Message: messageBytes,
                MessageType: "RAW",
                Signature: signature,
                SigningAlgorithm: signingAlgorithm,
            })
        );

        if (!verifyResp.SignatureValid) {
            throw new Error(`Warmup verify failed (invalid signature) for ${keyId}`);
        }
    }

    const results: LatencyVsConcurrencyResult = {};

    for (const concurrency of CONCURRENCY_LEVELS) {
        console.log(
            `KeyId: ${keyId}, payloadSize: ${PAYLOAD_SIZE}, concurrency: ${concurrency}, iterations: ${iterations}`
        );

        const signMs: number[] = [];
        const verifyMs: number[] = [];

        let remaining = iterations;

        while (remaining > 0) {
            const burstSize = Math.min(concurrency, remaining);

            const burstPromises = Array.from({ length: burstSize }, async () => {
                const s0 = performance.now();
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: messageBytes,
                        MessageType: "RAW",
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const s1 = performance.now();

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for ${keyId}`);

                const v0 = performance.now();
                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: messageBytes,
                        MessageType: "RAW",
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const v1 = performance.now();

                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }

                return { sign: s1 - s0, verify: v1 - v0 };
            });

            const burstResults = await Promise.all(burstPromises);
            for (const r of burstResults) {
                signMs.push(r.sign);
                verifyMs.push(r.verify);
            }

            remaining -= burstSize;

            // Wait between bursts to help throttling limits reset
            if (remaining > 0) {
                await sleep(SLEEP_BETWEEN_BURSTS_MS);
            }
        }

        results[concurrency.toString()] = { signMs, verifyMs };

        // Also wait between different concurrency levels
        await sleep(SLEEP_BETWEEN_BURSTS_MS);
    }

    return results;
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

    const results: TotalLatencyVsConcurrencyResult = [];
    for (const [keyId, signingAlgorithm] of entries) {
        const singleKeyResults = await latenciesVsConcurrency(
            keyId,
            iterations,
            signingAlgorithm
        );

        results.push({
            keyId,
            signingAlgorithm,
            results: singleKeyResults,
        });
    }

    return {
        iterations,
        payloadSize: PAYLOAD_SIZE,
        concurrencies: CONCURRENCY_LEVELS,
        results,
    };
};
