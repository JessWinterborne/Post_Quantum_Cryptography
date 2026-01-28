import { webcrypto as crypto } from "node:crypto";
import { kmac256 } from "@noble/hashes/sha3-addons.js";
import {
    ml_kem512,
    ml_kem768,
    ml_kem1024,
} from "@noble/post-quantum/ml-kem.js";
import { XWing } from "@noble/post-quantum/hybrid.js";

type EncapsulatedKem = {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
};

// ---------------------------------------------------
// ---------------------------------------------------
// Util Functions for conversions and encoding
// ---------------------------------------------------
// ---------------------------------------------------
const te = new TextEncoder();
const td = new TextDecoder();

export function utf8(s: string): Uint8Array {
    return te.encode(s);
}

export function utf8Decode(bytes: Uint8Array): string {
    return td.decode(bytes);
}

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

export function concatBytes(...arrs: Uint8Array[]): Uint8Array {
    const len = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

export function u32be(n: number): Uint8Array {
    const b = new Uint8Array(4);
    b[0] = (n >>> 24) & 0xff;
    b[1] = (n >>> 16) & 0xff;
    b[2] = (n >>> 8) & 0xff;
    b[3] = n & 0xff;
    return b;
}

export function randomBytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
}


// ---------------------------------------------------
// ---------------------------------------------------
// AES-GCM content encryption (JWE "enc")
// ---------------------------------------------------
// ---------------------------------------------------
export async function a256gcmEncrypt(
    cek: Uint8Array<ArrayBuffer>,
    iv: Uint8Array<ArrayBuffer>,
    plaintext: Uint8Array<ArrayBuffer>,
    aad: Uint8Array<ArrayBuffer>,
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    const key = await crypto.subtle.importKey(
        "raw",
        cek,
        { name: "AES-GCM" },
        false,
        ["encrypt"],
    );
    const ctBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        key,
        plaintext,
    );
    const ct = new Uint8Array(ctBuf);
    // WebCrypto appends tag to ciphertext; split last 16 bytes
    const tag = ct.slice(ct.length - 16);
    const ciphertext = ct.slice(0, ct.length - 16);
    return { ciphertext, tag };
}

export async function a256gcmDecrypt(
    cek: Uint8Array<ArrayBuffer>,
    iv: Uint8Array<ArrayBuffer>,
    ciphertext: Uint8Array<ArrayBuffer>,
    tag: Uint8Array<ArrayBuffer>,
    aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
        "raw",
        cek,
        { name: "AES-GCM" },
        false,
        ["decrypt"],
    );
    const combined = concatBytes(ciphertext, tag) as Uint8Array<ArrayBuffer>;
    const ptBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        key,
        combined,
    );
    return new Uint8Array(ptBuf);
}

// ---------------------------------------------------
// ---------------------------------------------------
// JOSE KDF using KMAC256
// ---------------------------------------------------
// ---------------------------------------------------
export function deriveCekWithKmac256(
    ssPrime: Uint8Array<ArrayBuffer>, // SS'
    encAlg: string, // "A256GCM"
    keyLenBits: number, // e.g. 256
): Uint8Array<ArrayBuffer> {
    const keyLenBytes = keyLenBits / 8;

    // AlgorithmID: length-prefixed enc alg name (Concat-KDF style)
    const algId = concatBytes(u32be(utf8(encAlg).length), utf8(encAlg));

    // SuppPubInfo: here we include keydatalen only (keyLenBits)
    const suppPubInfo = u32be(keyLenBits);

    // SuppPrivInfo is empty for this PoC
    const suppPrivInfo = new Uint8Array(0);

    // X = AlgorithmID || SuppPubInfo || SuppPrivInfo
    const X = concatBytes(algId, suppPubInfo, suppPrivInfo);

    // Draft’s JOSE KDF: KMAC256(K=SS', X, L, S="")
    // noble kmac256(kk, data) returns 32 bytes (256 bits) by default so don't need to specify L here
    const full = kmac256(ssPrime, X);

    if (full.length < keyLenBytes) {
        throw new Error("KMAC256 output shorter than required key length");
    }
    return full.slice(0, keyLenBytes); // SS (final shared secret) == CEK in Direct Key Agreement
}

// ---------------------------------------------------
// ---------------------------------------------------
// ML-KEM JWE Direct Key Agreement 
// ---------------------------------------------------
// ---------------------------------------------------
export async function encryptSignedJwtDirectMlKem(
    signedJwt: string,
    recipientPk: Uint8Array<ArrayBuffer>,
    encryptionAlgo: "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" | "X-Wing",
): Promise<string> {
    const alg = encryptionAlgo; // draft Figure 1 direct key agreement identifier
    const enc = "A256GCM"; // JWE content encryption alg (AEAD)

    // 1) PQ-KEM encapsulation (draft §4.2):
    //    (CT, SS') = Encap(pkR)
    let encapsulationResult: EncapsulatedKem;
    if (alg === "ML-KEM-512") {
        // const { cipherText: ct, sharedSecret: ssPrime }
        encapsulationResult = ml_kem512.encapsulate(recipientPk);
    } else if (alg === "ML-KEM-768") {
        // const { cipherText: ct, sharedSecret: ssPrime } =
        encapsulationResult = ml_kem768.encapsulate(recipientPk);
    } else if (alg === "ML-KEM-1024") {
        // const { cipherText: ct, sharedSecret: ssPrime } =
        encapsulationResult = ml_kem1024.encapsulate(recipientPk);
    } else if (alg === "X-Wing") {
        encapsulationResult = XWing.encapsulate(recipientPk);
    } else {
        throw new Error("Invalid algorthim");
    }
    const { cipherText: ct, sharedSecret: ssPrime } = encapsulationResult;

    // 2) Derive final shared secret SS via JOSE KDF (draft §5.1 + §4.2):
    //    For Direct Key Agreement, SS length MUST match enc key length.
    //    For A256GCM, CEK length is 256 bits.
    const cek = deriveCekWithKmac256(ssPrime as Uint8Array<ArrayBuffer>, enc, 256);

    // 3) Build JWE Protected Header (draft §6.1):
    //    "alg": "ML-KEM-512"
    //    "enc": "A256GCM"
    //    "ek" : base64url(CT)  (KEM ciphertext)
    //    "cty": "JWT" for nested JWS/JWT
    const protectedHeader = {
        alg: alg,
        enc: enc,
        cty: "JWT",
        ek: b64uEncode(ct), // CT goes into ek, must be base64url-encoded
    };
    const protectedBytes = utf8(JSON.stringify(protectedHeader));
    const protectedB64u = b64uEncode(protectedBytes);

    // 4) Content encryption (draft: CEK used with enc algorithm):
    //    Plaintext = signed JWT (inner JWS)
    const iv = randomBytes(12) as Uint8Array<ArrayBuffer>; // 96-bit IV for GCM - must be unique per encryption
    const aad = utf8(protectedB64u) as Uint8Array<ArrayBuffer>; // AAD is ASCII of protected header b64u
    const { ciphertext, tag } = await a256gcmEncrypt(
        cek,
        iv,
        utf8(signedJwt) as Uint8Array<ArrayBuffer>,
        aad,
    );

    const jweCompact =
        protectedB64u +
        "." +
        "" + // Direct Key Agreement: Encrypted Key field absent
        "." +
        b64uEncode(iv) +
        "." +
        b64uEncode(ciphertext) +
        "." +
        b64uEncode(tag);

    return jweCompact;
}

export async function decryptSignedJwtDirectMlKem(
    jweCompact: string,
    recipientSk: Uint8Array<ArrayBuffer>
): Promise<string> {
    const parts = jweCompact.split(".");
    if (parts.length !== 5) throw new Error("Invalid JWE compact serialisation");

    const [protB64u, encryptedKeyB64u, ivB64u, ctB64u, tagB64u] = parts;

    // In Direct Key Agreement, Encrypted Key MUST be absent => encryptedKeyB64u === ""
    if (encryptedKeyB64u !== "") {
        throw new Error(
            "Encrypted Key field must be empty in Direct Key Agreement",
        );
    }

    const protectedHeader = JSON.parse(utf8Decode(b64uDecode(protB64u)));

    const alg: string = protectedHeader.alg;
    const enc: string = protectedHeader.enc;
    if (
        !(
            alg === "ML-KEM-512" ||
            alg === "ML-KEM-768" ||
            alg === "ML-KEM-1024" ||
            alg === "X-Wing"
        )
    )
        throw new Error(`Unexpected alg: ${alg}`);

    // 1) Extract KEM ciphertext CT from header parameter "ek".
    const ct = b64uDecode(protectedHeader.ek);

    // 2) PQ-KEM decapsulation (draft §4.3):
    //    SS' = Decap(skR, CT)
    let ssPrime;
    if (alg === "ML-KEM-512") {
        ssPrime = ml_kem512.decapsulate(ct, recipientSk);
    } else if (alg === "ML-KEM-768") {
        ssPrime = ml_kem768.decapsulate(ct, recipientSk);
    } else if (alg === "ML-KEM-1024") {
        ssPrime = ml_kem1024.decapsulate(ct, recipientSk);
    } else if (alg === "X-Wing") {
        ssPrime = XWing.decapsulate(ct, recipientSk);
    } else {
        throw new Error("Invalid algorthim");
    }

    // 3) Derive CEK from SS' via JOSE KDF (draft §5.1 + §4.3):
    //    Same enc algorithm and key length as sender used.
    if (enc !== "A256GCM") throw new Error(`Unexpected enc: ${enc}`);
    const cek = deriveCekWithKmac256(ssPrime as Uint8Array<ArrayBuffer>, enc, 256);

    // 4) AEAD decryption using CEK:
    const iv = b64uDecode(ivB64u) as Uint8Array<ArrayBuffer>;
    const ciphertext = b64uDecode(ctB64u) as Uint8Array<ArrayBuffer>;
    const tag = b64uDecode(tagB64u) as Uint8Array<ArrayBuffer>;
    const aad = utf8(protB64u) as Uint8Array<ArrayBuffer>; // AAD is ASCII of protected header b64u

    const plaintextBytes = await a256gcmDecrypt(cek, iv, ciphertext, tag, aad);
    const signedJwt = utf8Decode(plaintextBytes);

    return signedJwt;
}

// Example usage (uncomment to run):
// (async () => {
//     // Generate recipient ML-KEM keypair
//     const recipientKeypair = ml_kem512.keygen();
//     const recipientPk = recipientKeypair.publicKey;
//     const recipientSk = recipientKeypair.secretKey;

//     const signedJwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

//     // Encrypt the signed JWT using ML-KEM Direct Key Agreement
//     const jweCompact = await encryptSignedJwtDirectMlKem(signedJwt, recipientPk as Uint8Array<ArrayBuffer>, "ML-KEM-512");
//     console.log("JWE Compact:", jweCompact);

//     // Decrypt the JWE to recover the signed JWT
//     const decryptedJwt = await decryptSignedJwtDirectMlKem(jweCompact, recipientSk as Uint8Array<ArrayBuffer>);
//     console.log("Decrypted JWT:", decryptedJwt);
// })();