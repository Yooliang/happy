import { z } from "zod";
import { type Fastify } from "../types";
import * as privacyKit from "privacy-kit";
import { db } from "@/storage/db";
import { auth } from "@/app/auth/auth";
import { log } from "@/utils/log";
import { createHash, createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { authenticate as ldapAuthenticate, cleanUsername as ldapCleanUsername } from "@/modules/ldap";

// ─── NAS credential encryption helpers ─────────────────────
function deriveNasCredKey(masterSecret: string, username: string): Buffer {
    return createHash('sha256').update(`nas-cred-key:${masterSecret}:${username}`).digest();
}

function encryptNasPassword(password: string, key: Buffer): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]); // 12 + 16 + N bytes
}

function decryptNasPassword(data: Buffer, key: Buffer): string {
    const iv = data.subarray(0, 12);
    const tag = data.subarray(12, 28);
    const encrypted = data.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

export function authRoutes(app: Fastify) {

    // ─── AD Login (username/password) ────────────────────────────
    app.post('/v1/auth/ad', {
        schema: {
            body: z.object({
                username: z.string().min(1),
                password: z.string().min(1)
            })
        }
    }, async (request, reply) => {
        const { username, password } = request.body;
        const normalizedUsername = ldapCleanUsername(username);
        log({ module: 'auth-ad' }, `AD login attempt: ${normalizedUsername}`);

        // Authenticate against AD via LDAP
        const result = await ldapAuthenticate(username, password);
        if (!result.success) {
            return reply.code(401).send({ error: 'Invalid credentials' });
        }

        // Derive a deterministic publicKey from MASTER_SECRET + username
        // This ensures the same user always maps to the same account
        const masterSecret = process.env.HANDY_MASTER_SECRET!;
        const publicKeyHash = createHash('sha256')
            .update(`ad:${masterSecret}:${normalizedUsername}`)
            .digest('hex');

        // Upsert account using the deterministic publicKey
        const user = await db.account.upsert({
            where: { publicKey: publicKeyHash },
            update: { updatedAt: new Date() },
            create: { publicKey: publicKeyHash }
        });

        // Derive a deterministic secret for encryption
        // Same user always gets the same secret, so they can decrypt their own data
        const secretHash = createHash('sha256')
            .update(`ad-secret:${masterSecret}:${normalizedUsername}`)
            .digest();
        const secret = Buffer.from(secretHash).toString("base64url");

        // Store encrypted NAS credentials for per-user NAS access
        try {
            const nasCredKey = deriveNasCredKey(masterSecret, normalizedUsername);
            const encryptedPassword = encryptNasPassword(password, nasCredKey);
            await db.userKVStore.upsert({
                where: { accountId_key: { accountId: user.id, key: 'nas-credentials' } },
                update: { value: encryptedPassword },
                create: { accountId: user.id, key: 'nas-credentials', value: encryptedPassword },
            });
            log({ module: 'auth-ad' }, `NAS credentials stored for ${normalizedUsername}`);
        } catch (e: any) {
            log({ module: 'auth-ad' }, `Failed to store NAS credentials: ${e?.message}`);
        }

        const token = await auth.createToken(user.id);
        log({ module: 'auth-ad' }, `AD login success: ${normalizedUsername} → account ${user.id}`);

        return reply.send({
            success: true,
            token,
            secret
        });
    });

    // ─── Retrieve NAS credentials for per-user access ─────────
    app.get('/v1/auth/ad/nas-credentials', {
        preHandler: app.authenticate,
        schema: {
            querystring: z.object({
                username: z.string().min(1),
            }),
        }
    }, async (request, reply) => {
        const normalizedUsername = ldapCleanUsername(request.query.username);
        const masterSecret = process.env.HANDY_MASTER_SECRET!;

        const kv = await db.userKVStore.findUnique({
            where: { accountId_key: { accountId: request.userId, key: 'nas-credentials' } },
        });

        if (!kv || !kv.value) {
            return reply.code(404).send({ error: 'No NAS credentials found. Please log in again.' });
        }

        try {
            const nasCredKey = deriveNasCredKey(masterSecret, normalizedUsername);
            const decryptedPassword = decryptNasPassword(Buffer.from(kv.value), nasCredKey);
            return reply.send({ username: normalizedUsername, password: decryptedPassword });
        } catch (e: any) {
            log({ module: 'auth-ad' }, `Failed to decrypt NAS credentials for ${normalizedUsername}: ${e?.message}`);
            return reply.code(500).send({ error: 'Failed to decrypt credentials' });
        }
    });

    app.post('/v1/auth', {
        schema: {
            body: z.object({
                publicKey: z.string(),
                challenge: z.string(),
                signature: z.string()
            })
        }
    }, async (request, reply) => {
        const tweetnacl = (await import("tweetnacl")).default;
        const publicKey = privacyKit.decodeBase64(request.body.publicKey);
        const challenge = privacyKit.decodeBase64(request.body.challenge);
        const signature = privacyKit.decodeBase64(request.body.signature);
        const isValid = tweetnacl.sign.detached.verify(challenge, signature, publicKey);
        if (!isValid) {
            return reply.code(401).send({ error: 'Invalid signature' });
        }

        // Create or update user in database
        const publicKeyHex = privacyKit.encodeHex(publicKey);
        const user = await db.account.upsert({
            where: { publicKey: publicKeyHex },
            update: { updatedAt: new Date() },
            create: { publicKey: publicKeyHex }
        });

        return reply.send({
            success: true,
            token: await auth.createToken(user.id)
        });
    });

    app.post('/v1/auth/request', {
        schema: {
            body: z.object({
                publicKey: z.string(),
                supportsV2: z.boolean().nullish()
            }),
            response: {
                200: z.union([z.object({
                    state: z.literal('requested'),
                }), z.object({
                    state: z.literal('authorized'),
                    token: z.string(),
                    response: z.string()
                })]),
                401: z.object({
                    error: z.literal('Invalid public key')
                })
            }
        }
    }, async (request, reply) => {
        const tweetnacl = (await import("tweetnacl")).default;
        const publicKey = privacyKit.decodeBase64(request.body.publicKey);
        const isValid = tweetnacl.box.publicKeyLength === publicKey.length;
        if (!isValid) {
            return reply.code(401).send({ error: 'Invalid public key' });
        }

        const publicKeyHex = privacyKit.encodeHex(publicKey);
        log({ module: 'auth-request' }, `Terminal auth request - publicKey hex: ${publicKeyHex}`);

        const answer = await db.terminalAuthRequest.upsert({
            where: { publicKey: publicKeyHex },
            update: {},
            create: { publicKey: publicKeyHex, supportsV2: request.body.supportsV2 ?? false }
        });

        if (answer.response && answer.responseAccountId) {
            const token = await auth.createToken(answer.responseAccountId!, { session: answer.id });
            return reply.send({
                state: 'authorized',
                token: token,
                response: answer.response
            });
        }

        return reply.send({ state: 'requested' });
    });

    // Get auth request status
    app.get('/v1/auth/request/status', {
        schema: {
            querystring: z.object({
                publicKey: z.string(),
            }),
            response: {
                200: z.object({
                    status: z.enum(['not_found', 'pending', 'authorized']),
                    supportsV2: z.boolean()
                })
            }
        }
    }, async (request, reply) => {
        const tweetnacl = (await import("tweetnacl")).default;
        const publicKey = privacyKit.decodeBase64(request.query.publicKey);
        const isValid = tweetnacl.box.publicKeyLength === publicKey.length;
        if (!isValid) {
            return reply.send({ status: 'not_found', supportsV2: false });
        }

        const publicKeyHex = privacyKit.encodeHex(publicKey);
        const authRequest = await db.terminalAuthRequest.findUnique({
            where: { publicKey: publicKeyHex }
        });

        if (!authRequest) {
            return reply.send({ status: 'not_found', supportsV2: false });
        }

        if (authRequest.response && authRequest.responseAccountId) {
            return reply.send({ status: 'authorized', supportsV2: false });
        }

        return reply.send({ status: 'pending', supportsV2: authRequest.supportsV2 });
    });

    // Approve auth request
    app.post('/v1/auth/response', {
        preHandler: app.authenticate,
        schema: {
            body: z.object({
                response: z.string(),
                publicKey: z.string()
            })
        }
    }, async (request, reply) => {
        log({ module: 'auth-response' }, `Auth response endpoint hit - user: ${request.userId}, publicKey: ${request.body.publicKey.substring(0, 20)}...`);
        const tweetnacl = (await import("tweetnacl")).default;
        const publicKey = privacyKit.decodeBase64(request.body.publicKey);
        const isValid = tweetnacl.box.publicKeyLength === publicKey.length;
        if (!isValid) {
            log({ module: 'auth-response' }, `Invalid public key length: ${publicKey.length}`);
            return reply.code(401).send({ error: 'Invalid public key' });
        }
        const publicKeyHex = privacyKit.encodeHex(publicKey);
        log({ module: 'auth-response' }, `Looking for auth request with publicKey hex: ${publicKeyHex}`);
        const authRequest = await db.terminalAuthRequest.findUnique({
            where: { publicKey: publicKeyHex }
        });
        if (!authRequest) {
            log({ module: 'auth-response' }, `Auth request not found for publicKey: ${publicKeyHex}`);
            // Let's also check what auth requests exist
            const allRequests = await db.terminalAuthRequest.findMany({
                take: 5,
                orderBy: { createdAt: 'desc' }
            });
            log({ module: 'auth-response' }, `Recent auth requests in DB: ${JSON.stringify(allRequests.map(r => ({ id: r.id, publicKey: r.publicKey.substring(0, 20) + '...', hasResponse: !!r.response })))}`);
            return reply.code(404).send({ error: 'Request not found' });
        }
        if (!authRequest.response) {
            await db.terminalAuthRequest.update({
                where: { id: authRequest.id },
                data: { response: request.body.response, responseAccountId: request.userId }
            });
        }
        return reply.send({ success: true });
    });

    // Account auth request
    app.post('/v1/auth/account/request', {
        schema: {
            body: z.object({
                publicKey: z.string(),
            }),
            response: {
                200: z.union([z.object({
                    state: z.literal('requested'),
                }), z.object({
                    state: z.literal('authorized'),
                    token: z.string(),
                    response: z.string()
                })]),
                401: z.object({
                    error: z.literal('Invalid public key')
                })
            }
        }
    }, async (request, reply) => {
        const tweetnacl = (await import("tweetnacl")).default;
        const publicKey = privacyKit.decodeBase64(request.body.publicKey);
        const isValid = tweetnacl.box.publicKeyLength === publicKey.length;
        if (!isValid) {
            return reply.code(401).send({ error: 'Invalid public key' });
        }

        const answer = await db.accountAuthRequest.upsert({
            where: { publicKey: privacyKit.encodeHex(publicKey) },
            update: {},
            create: { publicKey: privacyKit.encodeHex(publicKey) }
        });

        if (answer.response && answer.responseAccountId) {
            const token = await auth.createToken(answer.responseAccountId!);
            return reply.send({
                state: 'authorized',
                token: token,
                response: answer.response
            });
        }

        return reply.send({ state: 'requested' });
    });

    // Approve account auth request
    app.post('/v1/auth/account/response', {
        preHandler: app.authenticate,
        schema: {
            body: z.object({
                response: z.string(),
                publicKey: z.string()
            })
        }
    }, async (request, reply) => {
        const tweetnacl = (await import("tweetnacl")).default;
        const publicKey = privacyKit.decodeBase64(request.body.publicKey);
        const isValid = tweetnacl.box.publicKeyLength === publicKey.length;
        if (!isValid) {
            return reply.code(401).send({ error: 'Invalid public key' });
        }
        const authRequest = await db.accountAuthRequest.findUnique({
            where: { publicKey: privacyKit.encodeHex(publicKey) }
        });
        if (!authRequest) {
            return reply.code(404).send({ error: 'Request not found' });
        }
        if (!authRequest.response) {
            await db.accountAuthRequest.update({
                where: { id: authRequest.id },
                data: { response: request.body.response, responseAccountId: request.userId }
            });
        }
        return reply.send({ success: true });
    });

}