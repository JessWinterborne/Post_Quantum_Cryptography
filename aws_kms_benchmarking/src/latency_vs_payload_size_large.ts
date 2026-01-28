import {
    KMSClient,
    SignCommand,
    VerifyCommand,
    GetPublicKeyCommand,
    SigningAlgorithmSpec,
} from "@aws-sdk/client-kms";
import { createHash, randomUUID } from "crypto";
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

function u8(b: Buffer): Uint8Array {
    return new Uint8Array(b);
}

function sha256(msg: Uint8Array): Uint8Array {
    return u8(createHash("sha256").update(Buffer.from(msg)).digest());
}

// Node supports SHAKE256 XOF using outputLength
function shake256(msg: Uint8Array, outLen: number): Uint8Array {
    return u8(createHash("shake256", { outputLength: outLen }).update(Buffer.from(msg)).digest());
}

function concatU8(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((s, p) => s + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

/**
 * Minimal DER/SPKI parser to extract subjectPublicKey BIT STRING bytes.
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
 */
function readDerLen(buf: Uint8Array, offset: number): { len: number; next: number } {
    const b = buf[offset];
    if (b < 0x80) return { len: b, next: offset + 1 };
    const n = b & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[offset + 1 + i];
    return { len, next: offset + 1 + n };
}

function expectTag(
    buf: Uint8Array,
    offset: number,
    tag: number
): { start: number; end: number; next: number } {
    if (buf[offset] !== tag) {
        throw new Error(`DER parse error: expected tag 0x${tag.toString(16)} at ${offset}`);
    }
    const { len, next } = readDerLen(buf, offset + 1);
    const start = next;
    const end = start + len;
    return { start, end, next: end };
}

function extractSubjectPublicKeyBytesFromSpki(spkiDer: Uint8Array): Uint8Array {
    const outer = expectTag(spkiDer, 0, 0x30); // SEQUENCE
    const alg = expectTag(spkiDer, outer.start, 0x30); // algorithm SEQUENCE
    const bitStr = expectTag(spkiDer, alg.next, 0x03); // BIT STRING
    const unusedBits = spkiDer[bitStr.start];
    if (unusedBits !== 0) throw new Error(`Unexpected BIT STRING unused bits = ${unusedBits}`);
    return spkiDer.slice(bitStr.start + 1, bitStr.end);
}

// --- Cache per key for ML-DSA: pkHash = SHAKE256(subjectPublicKey, 64) ---
const mlDsaPkHashCache = new Map<string, Uint8Array>();

async function getMlDsaPkHash64(keyId: string): Promise<Uint8Array> {
    const cached = mlDsaPkHashCache.get(keyId);
    if (cached) return cached;

    const pub = await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));
    if (!pub.PublicKey) throw new Error(`GetPublicKey returned no PublicKey for ${keyId}`);

    const subjectPubKeyBytes = extractSubjectPublicKeyBytesFromSpki(pub.PublicKey);
    const pkHash = shake256(subjectPubKeyBytes, 64);
    mlDsaPkHashCache.set(keyId, pkHash);
    return pkHash;
}

/**
 * Compute μ for ML-DSA per AWS’ EXTERNAL_MU scheme:
 *   μ = SHAKE256( pkHash || domSep || ctxLen || ctx || message, 64 )
 * This uses default domSep=0x00 and empty ctx (ctxLen=0x00).
 */
async function computeExternalMu64(keyId: string, message: Uint8Array): Promise<Uint8Array> {
    const pkHash = await getMlDsaPkHash64(keyId);
    const prefix = new Uint8Array([0x00, 0x00]); // domSep=0x00, ctxLen=0x00 (no context)
    return shake256(concatU8(pkHash, prefix, message), 64);
}

type PreparedKmsMessage = {
    messageType: "DIGEST" | "EXTERNAL_MU";
    message: Uint8Array; // digest bytes or μ bytes
};

async function prepareKmsMessage(
    keyId: string,
    signingAlgorithm: SigningAlgorithmSpec,
    rawMessageBytes: Uint8Array
): Promise<PreparedKmsMessage> {
    if (signingAlgorithm === SigningAlgorithmSpec.ECDSA_SHA_256) {
        return { messageType: "DIGEST", message: sha256(rawMessageBytes) };
    }
    if (signingAlgorithm === SigningAlgorithmSpec.ML_DSA_SHAKE_256) {
        return { messageType: "EXTERNAL_MU", message: await computeExternalMu64(keyId, rawMessageBytes) };
    }
    throw new Error(`Unsupported signing algorithm: ${signingAlgorithm}`);
}

async function latenciesVsPayloadSize(keyId: string, iterations: number, signingAlgorithm: SigningAlgorithmSpec) {
    // If ML-DSA, ensure pkHash is cached once up-front
    if (signingAlgorithm === SigningAlgorithmSpec.ML_DSA_SHAKE_256) {
        await getMlDsaPkHash64(keyId);
    }

    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const results: LatencyVsPayloadSizeResult = {};

    // Generate payloads of increasing size
    for (let len = 200; len <= 20000; len += 2000) {
        let messagePayload = "";
        for (let i = 0; i < len; i++) {
            messagePayload += chars[Math.floor(Math.random() * chars.length)];
        }

        const rawMessageBytes = utf8Bytes(messagePayload);

        // IMPORTANT: never use RAW. Always prepare digest/μ once per payload size.
        const prepared = await prepareKmsMessage(keyId, signingAlgorithm, rawMessageBytes);

        console.log(
            `KeyId: ${keyId}, Len: ${len}, Mode: ${prepared.messageType} (${prepared.message.length} bytes)`
        );

        const useParallel = process.env.USE_PARALLEL === "true" || false;

        if (useParallel) {
            // Pre-warm
            const testPromises = Array.from({ length: 50 }, async () => {
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: prepared.message,
                        MessageType: prepared.messageType as any, // keeps compatibility across SDK minor versions
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: prepared.message,
                        MessageType: prepared.messageType as any,
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }
            });
            await Promise.all(testPromises);

            // Parallel version
            const promises = Array.from({ length: iterations }, async () => {
                const s0 = performance.now();
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: prepared.message,
                        MessageType: prepared.messageType as any, // keeps compatibility across SDK minor versions
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
                        Message: prepared.message,
                        MessageType: prepared.messageType as any,
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );
                const v1 = performance.now();

                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }

                return { signMs: s1 - s0, verifyMs: v1 - v0 };
            });

            const iterationResults = await Promise.all(promises);
            results[len.toString()] = {
                signMs: iterationResults.map((r) => r.signMs),
                verifyMs: iterationResults.map((r) => r.verifyMs),
            };
        } else {
            const signMs: number[] = [];
            const verifyMs: number[] = [];

            // Pre-warm KMS client for this payload size
            for (let i = 0; i < 20; i++) {
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: prepared.message,
                        MessageType: prepared.messageType as any,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                const signature = signResp.Signature;
                if (!signature) throw new Error(`KMS Sign returned no Signature for key ${keyId}`);

                const verifyResp = await kms.send(
                    new VerifyCommand({
                        KeyId: keyId,
                        Message: prepared.message,
                        MessageType: prepared.messageType as any,
                        Signature: signature,
                        SigningAlgorithm: signingAlgorithm,
                    })
                );

                if (!verifyResp.SignatureValid) {
                    throw new Error(`Signature invalid for key ${keyId}`);
                }
            }

            // Run actual measurements serially
            for (let i = 0; i < iterations; i++) {
                const s0 = performance.now();
                const signResp = await kms.send(
                    new SignCommand({
                        KeyId: keyId,
                        Message: prepared.message,
                        MessageType: prepared.messageType as any,
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
                        Message: prepared.message,
                        MessageType: prepared.messageType as any,
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

            results[len.toString()] = { signMs, verifyMs };
        }
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

    // Warm-up each key once to reduce cold-start variability (still never RAW)
    for (const [keyId, signingAlgorithm] of entries) {
        if (signingAlgorithm === SigningAlgorithmSpec.ML_DSA_SHAKE_256) {
            await getMlDsaPkHash64(keyId); // cache pkHash
        }

        const rawWarmupMsg = utf8Bytes(
            JSON.stringify({ now: Date.now(), nonce: randomUUID(), warmup: true })
        );

        const prepared = await prepareKmsMessage(keyId, signingAlgorithm, rawWarmupMsg);

        await kms.send(
            new SignCommand({
                KeyId: keyId,
                Message: prepared.message,
                MessageType: prepared.messageType as any,
                SigningAlgorithm: signingAlgorithm,
            })
        );
    }

    const results: TotalLatencyVsPayloadSizeResult = [];
    for (const [keyId, signingAlgorithm] of entries.reverse()) {
        const singleKeyResults = await latenciesVsPayloadSize(keyId, iterations, signingAlgorithm);
        results.push({
            keyId,
            signingAlgorithm,
            results: singleKeyResults,
        });
    }

    return { iterations, results };
};
