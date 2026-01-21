/**
 * Secure Messaging - Client-Side Cryptography Module
 * Implements ECDH key exchange, AES-256-GCM encryption, and RSA-SHA256 signatures
 */

const CryptoModule = (function() {
    'use strict';

    const ECDH_CURVE = 'P-256';
    const RSA_MODULUS_LENGTH = 2048;
    const AES_KEY_LENGTH = 256;
    const SESSION_KEY_LIFETIME_MS = 300000; // 5 minutes

    // Session key cache
    const sessionKeys = new Map();

    /**
     * Generate ECDH key pair for key exchange
     */
    async function generateECDHKeyPair() {
        return await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: ECDH_CURVE },
            true,
            ['deriveKey', 'deriveBits']
        );
    }

    /**
     * Generate RSA key pair for digital signatures
     */
    async function generateRSAKeyPair() {
        return await window.crypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: RSA_MODULUS_LENGTH,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['sign', 'verify']
        );
    }

    /**
     * Export public key to Base64 string
     */
    async function exportPublicKey(publicKey) {
        const exported = await window.crypto.subtle.exportKey('spki', publicKey);
        return arrayBufferToBase64(exported);
    }

    /**
     * Export private key to Base64 string
     */
    async function exportPrivateKey(privateKey) {
        const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);
        return arrayBufferToBase64(exported);
    }

    /**
     * Import ECDH public key from Base64 string
     */
    async function importECDHPublicKey(keyB64) {
        const keyData = base64ToArrayBuffer(keyB64);
        return await window.crypto.subtle.importKey(
            'spki',
            keyData,
            { name: 'ECDH', namedCurve: ECDH_CURVE },
            false,
            []
        );
    }

    /**
     * Import ECDH private key from Base64 string
     */
    async function importECDHPrivateKey(keyB64) {
        const keyData = base64ToArrayBuffer(keyB64);
        return await window.crypto.subtle.importKey(
            'pkcs8',
            keyData,
            { name: 'ECDH', namedCurve: ECDH_CURVE },
            false,
            ['deriveKey', 'deriveBits']
        );
    }

    /**
     * Import RSA public key from Base64 string
     */
    async function importRSAPublicKey(keyB64) {
        const keyData = base64ToArrayBuffer(keyB64);
        return await window.crypto.subtle.importKey(
            'spki',
            keyData,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['verify']
        );
    }

    /**
     * Import RSA private key from Base64 string
     */
    async function importRSAPrivateKey(keyB64) {
        const keyData = base64ToArrayBuffer(keyB64);
        return await window.crypto.subtle.importKey(
            'pkcs8',
            keyData,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['sign']
        );
    }

    /**
     * Derive AES-256 session key using ECDH
     */
    async function deriveSessionKey(privateKey, publicKey) {
        return await window.crypto.subtle.deriveKey(
            { name: 'ECDH', public: publicKey },
            privateKey,
            { name: 'AES-GCM', length: AES_KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Get or create session key with automatic rotation
     */
    async function getSessionKey(sessionId, myPrivateKeyB64, otherPublicKeyB64) {
        const cached = sessionKeys.get(sessionId);
        const now = Date.now();

        if (cached && (now - cached.createdAt) < SESSION_KEY_LIFETIME_MS) {
            return cached.key;
        }

        console.log('Deriving new session key for:', sessionId);

        const myPrivateKey = await importECDHPrivateKey(myPrivateKeyB64);
        const otherPublicKey = await importECDHPublicKey(otherPublicKeyB64);
        const sessionKey = await deriveSessionKey(myPrivateKey, otherPublicKey);

        sessionKeys.set(sessionId, {
            key: sessionKey,
            createdAt: now
        });

        return sessionKey;
    }

    /**
     * Encrypt message with AES-256-GCM
     */
    async function encryptMessage(message, sessionKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const timestamp = Date.now();
        const nonce = window.crypto.getRandomValues(new Uint8Array(16));

        // Create additional authenticated data (AAD)
        const aad = new TextEncoder().encode(JSON.stringify({
            timestamp: timestamp,
            nonce: arrayBufferToBase64(nonce)
        }));

        const encodedMessage = new TextEncoder().encode(message);

        const ciphertext = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: aad
            },
            sessionKey,
            encodedMessage
        );

        return {
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext),
            timestamp: timestamp,
            nonce: arrayBufferToBase64(nonce)
        };
    }

    /**
     * Decrypt message with AES-256-GCM
     */
    async function decryptMessage(encryptedData, sessionKey) {
        const iv = base64ToArrayBuffer(encryptedData.iv);
        const ciphertext = base64ToArrayBuffer(encryptedData.ciphertext);

        // Recreate AAD
        const aad = new TextEncoder().encode(JSON.stringify({
            timestamp: encryptedData.timestamp,
            nonce: encryptedData.nonce
        }));

        try {
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: aad
                },
                sessionKey,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        } catch (e) {
            console.error('Decryption failed:', e);
            throw new Error('Message decryption failed - possible tampering detected');
        }
    }

    /**
     * Sign message with RSA-SHA256
     */
    async function signMessage(message, privateKeyB64) {
        const privateKey = await importRSAPrivateKey(privateKeyB64);
        const timestamp = Date.now();

        // Include timestamp in signature
        const dataToSign = JSON.stringify({
            message: message,
            timestamp: timestamp
        });

        const signature = await window.crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            privateKey,
            new TextEncoder().encode(dataToSign)
        );

        return {
            signature: arrayBufferToBase64(signature),
            timestamp: timestamp
        };
    }

    /**
     * Verify message signature with RSA-SHA256
     */
    async function verifySignature(message, signatureB64, timestamp, publicKeyB64) {
        const publicKey = await importRSAPublicKey(publicKeyB64);

        const dataToVerify = JSON.stringify({
            message: message,
            timestamp: timestamp
        });

        const signature = base64ToArrayBuffer(signatureB64);

        return await window.crypto.subtle.verify(
            'RSASSA-PKCS1-v1_5',
            publicKey,
            signature,
            new TextEncoder().encode(dataToVerify)
        );
    }

    /**
     * Calculate key fingerprint (SHA-256 hash, first 16 chars)
     */
    async function calculateFingerprint(keyB64) {
        const keyData = base64ToArrayBuffer(keyB64);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', keyData);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(':');
    }

    /**
     * Generate random salt for key derivation
     */
    function generateSalt() {
        const salt = window.crypto.getRandomValues(new Uint8Array(32));
        return arrayBufferToBase64(salt);
    }

    /**
     * Check if replay attack (timestamp too old)
     */
    function isReplayAttack(timestamp, maxAgeMs = 60000) {
        return (Date.now() - timestamp) > maxAgeMs;
    }

    /**
     * Clear session key (for rotation)
     */
    function clearSessionKey(sessionId) {
        sessionKeys.delete(sessionId);
    }

    /**
     * Clear all session keys
     */
    function clearAllSessionKeys() {
        sessionKeys.clear();
    }

    // Utility functions
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Public API
    return {
        generateECDHKeyPair,
        generateRSAKeyPair,
        exportPublicKey,
        exportPrivateKey,
        importECDHPublicKey,
        importECDHPrivateKey,
        importRSAPublicKey,
        importRSAPrivateKey,
        deriveSessionKey,
        getSessionKey,
        encryptMessage,
        decryptMessage,
        signMessage,
        verifySignature,
        calculateFingerprint,
        generateSalt,
        isReplayAttack,
        clearSessionKey,
        clearAllSessionKeys,
        arrayBufferToBase64,
        base64ToArrayBuffer
    };
})();

// Make globally available
window.CryptoModule = CryptoModule;
