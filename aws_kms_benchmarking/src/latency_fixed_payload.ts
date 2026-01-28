import {
    KMSClient,
    SignCommand,
    VerifyCommand,
    GetPublicKeyCommand,
    SigningAlgorithmSpec
} from "@aws-sdk/client-kms";
import { randomUUID, sign } from "crypto";
import { performance } from "perf_hooks";

type Summary = {
    n: number;
    min: number;
    p50: number;
    p90: number;
    p99: number;
    max: number;
    mean: number;
};

type KeyRun = {
    keyId: string;
    iterations: number;
    signingAlgorithm: string;
    summary: {
        signMs: Summary;
        verifyMs: Summary;
        roundtripMs: Summary;
    } | null;
    signMs: number[];
    verifyMs: number[];
    roundtripMs: number[];
};

const kms = new KMSClient({});

function utf8Bytes(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

function summarise(ms: number[]): Summary {
    const sorted = [...ms].sort((a, b) => a - b);
    const pick = (p: number) => sorted[Math.floor(p * (sorted.length - 1))];
    const mean = ms.reduce((a, b) => a + b, 0) / ms.length;
    return {
        n: ms.length,
        min: sorted[0],
        p50: pick(0.5),
        p90: pick(0.9),
        p99: pick(0.99),
        max: sorted[sorted.length - 1],
        mean,
    };
}

async function runForKey(keyId: string, iterations: number, signingAlgorithm: SigningAlgorithmSpec): Promise<KeyRun> {
    // Fetch once (optional, but helps avoid per-iteration extra work)
    await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));

    const signMs: number[] = [];
    const verifyMs: number[] = [];
    const roundtripMs: number[] = [];

    for (let i = 0; i < iterations; i++) {
        const payloadObj = {
            coreIdentityJWT: {
                // Taken from:
                // https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/prove-users-identity/#understand-your-user-s-core-identity-claim
                sub: "urn:fdc:gov.uk:2022:56P4CMsGh_02YOlWpd8PAOI-2sVlB2nsNU7mcLZYhYw=",
                iss: "https://identity.integration.account.gov.uk/",
                // Re create each time to ensure signature changes
                // to avoid any caching
                aud: randomUUID(),
                nbf: Date.now(),
                iat: Date.now(),
                exp: Date.now() + 100000,
                vot: "P2",
                vtm: "https://oidc.integration.account.gov.uk/trustmark",
                vc: {},
            },
            address: {},
            passport: {},
            drivingPermit: {},
            returnCode: {},
        };

        const message = utf8Bytes(JSON.stringify(payloadObj));

        const t0 = performance.now();

        const s0 = performance.now();
        const signResp = await kms.send(
            new SignCommand({
                KeyId: keyId,
                Message: message,
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
                Message: message,
                MessageType: "RAW",
                Signature: signature,
                SigningAlgorithm: signingAlgorithm,
            })
        );
        const v1 = performance.now();

        const t1 = performance.now();

        if (!verifyResp.SignatureValid) {
            throw new Error(`Signature invalid for key ${keyId}`);
        }

        signMs.push(s1 - s0);
        verifyMs.push(v1 - v0);
        roundtripMs.push(t1 - t0);
    }

    return {
        keyId,
        iterations,
        signingAlgorithm,
        summary: {
            signMs: summarise(signMs),
            verifyMs: summarise(verifyMs),
            roundtripMs: summarise(roundtripMs)
        },
        signMs: signMs,
        verifyMs: verifyMs,
        roundtripMs: roundtripMs,
    };
}

// Lambda handler
export const handler = async (event: any) => {
    const mlDsa44Arn = process.env.ML_DSA_44_ARN;
    const mlDsa65Arn = process.env.ML_DSA_65_ARN;
    const mlDsa87Arn = process.env.ML_DSA_87_ARN;
    const eccP256Arn = process.env.ECC_NIST_P256_ARN;

    const keyAlgMap: Record<string, SigningAlgorithmSpec> = {};

    // if (mlDsa44Arn) keyAlgMap[mlDsa44Arn] = "ML_DSA_SHAKE_256";
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

    const results: KeyRun[] = [];
    for (const [keyId, signingAlgorithm] of entries) {
        results.push(await runForKey(keyId, iterations, signingAlgorithm));
    }

    return {
        iterations,
        results
    };
};
