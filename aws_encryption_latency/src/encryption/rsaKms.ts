import { importJWK, CompactEncrypt } from "jose";
import { KMSClient, DecryptCommand } from "@aws-sdk/client-kms";
import { createDecipheriv } from "crypto";

function _b64decode(s: string): Buffer {
    const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
    return Buffer.from(b64, "base64");
}

export function b64uDecode(s: string): string {
    const buffer = _b64decode(s)
    return buffer.toString("utf8");
}

export function b64uDecodeBuf(s: string): Buffer {
    const buffer = _b64decode(s)
    return buffer;
}

export type ALLOWED_ALGORITHMS = "ES256" | "ML-DSA-65" | "ES256-ML-DSA-65" | "RSA-OAEP-256" | "ML-KEM-768" | "X-Wing";

export type JWK = {
    kty: string;
    n?: string;
    e?: string;
    crv?: string;
    kid?: string;
    use?: "sig" | "enc";
    alg?: ALLOWED_ALGORITHMS;
    customPub?: string | Uint8Array<ArrayBufferLike>; // For AKP (ML-KEM)
    customPriv?: string | Uint8Array<ArrayBufferLike>; // For AKP (ML-KEM) private key
}

export type JWKS = JWK[];

export async function encryptJwtRsa(jwsCompact: string, jwks: JWKS): Promise<string> {
    // Input jws is already base64url-encoded

    console.log("Encrypting JWT using RSA-OAEP-256 and A256GCM");
    // Pick the RSA public JWK.
    const rsaJwk =
        jwks.find((k: JWK) => k.kty === "RSA" && k.use === "enc")

    if (!rsaJwk) {
        throw new Error("No RSA key found in JWKS/JWK.");
    }

    console.log("Found RSA JWK", rsaJwk);

    // Import the JWK into a KeyLike object jose can use for encryption.
    const publicKey = await importJWK(rsaJwk, "RSA-OAEP-256");
    console.log("Imported RSA public key");

    // Convert the JWS string into bytes (this becomes the plaintext for the JWE).
    const plaintext = new TextEncoder().encode(jwsCompact);

    // Create the JWE encrypter and set the protected header
    const encrypter = new CompactEncrypt(plaintext).setProtectedHeader({
        alg: "RSA-OAEP-256",
        enc: "A256GCM",
        // Optional: include kid 
        ...(rsaJwk.kid ? { kid: rsaJwk.kid } : {}),
    });

    // Encrypt to produce compact JWE
    const jweCompact = await encrypter.encrypt(publicKey);

    return jweCompact;
}

export async function decryptJwtRsa(jweCompact: string, kmsKeyArn: string): Promise<string> {

    console.log("Decrypting JWT using KMS RSA-OAEP-256 and A256GCM");

    // Initialise KMS client
    console.log("Initialising KMS client");
    const kms = new KMSClient({});

    // Split JWE into parts
    const parts = jweCompact.split(".");
    if (parts.length !== 5) {
        throw new Error("Invalid compact JWE: expected 5 parts.");
    }
    const [protectedB64u, encryptedKeyB64u, ivB64u, ciphertextB64u, tagB64u] = parts;

    // Decode and parse the protected header JSON
    const protectedHeaderJson = b64uDecode(protectedB64u);
    const protectedHeader = JSON.parse(protectedHeaderJson) as { alg?: string; enc?: string; kid?: string };

    // Validate header
    if (protectedHeader.alg !== "RSA-OAEP-256") {
        throw new Error(`Unsupported JWE alg: ${protectedHeader.alg}`);
    }
    if (protectedHeader.enc !== "A256GCM") {
        throw new Error(`Unsupported JWE enc: ${protectedHeader.enc}`);
    }
    console.log("JWE protected header:", protectedHeader);

    // Use KMS to decrypt the JWE "encrypted key" (the wrapped CEK)
    const encryptedKey = b64uDecodeBuf(encryptedKeyB64u);

    console.log("Calling KMS Decrypt to unwrap CEK");
    const kmsResponse = await kms.send(
        new DecryptCommand({
            KeyId: kmsKeyArn,
            CiphertextBlob: encryptedKey,
            EncryptionAlgorithm: "RSAES_OAEP_SHA_256",
        })
    );

    if (!kmsResponse.Plaintext) {
        throw new Error("KMS did not return a CEK");
    }

    const cek = Buffer.from(kmsResponse.Plaintext as Uint8Array);

    // A256GCM requires a 32-byte CEK
    if (cek.length !== 32) {
        throw new Error(`Invalid CEK length: ${cek.length}`);
    }

    // 5) AES-256-GCM decryption
    const iv = b64uDecodeBuf(ivB64u);
    const ciphertext = b64uDecodeBuf(ciphertextB64u);
    const authTag = b64uDecodeBuf(tagB64u);

    // AAD is the ASCII bytes of the protected header (base64url form)
    const aad = Buffer.from(protectedB64u, "ascii");

    const decipher = createDecipheriv("aes-256-gcm", cek, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);

    console.log("Decryption complete, plaintext:", plaintext.toString("utf8"));

    // Plaintext is original compact JWS
    return plaintext.toString("utf8");
}