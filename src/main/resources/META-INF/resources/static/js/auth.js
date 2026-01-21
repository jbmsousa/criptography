/**
 * Secure Messaging - Authentication Module
 * Handles user registration, login, and session management
 */

const AuthModule = (function() {
    'use strict';

    const TOKEN_KEY = 'authToken';
    const USER_ID_KEY = 'userId';
    const ECDH_PRIVATE_KEY = 'ecdhPrivateKey';
    const RSA_PRIVATE_KEY = 'rsaPrivateKey';

    /**
     * Register new user with generated key pairs
     */
    async function register(userId, password, onProgress) {
        try {
            if (onProgress) onProgress('Validating input...');

            if (!userId || userId.length < 3) {
                throw new Error('User ID must be at least 3 characters');
            }
            if (!password || password.length < 8) {
                throw new Error('Password must be at least 8 characters');
            }

            if (onProgress) onProgress('Generating ECDH key pair...');

            // Generate ECDH key pair for key exchange
            const ecdhKeyPair = await CryptoModule.generateECDHKeyPair();
            const ecdhPublicKey = await CryptoModule.exportPublicKey(ecdhKeyPair.publicKey);
            const ecdhPrivateKey = await CryptoModule.exportPrivateKey(ecdhKeyPair.privateKey);

            if (onProgress) onProgress('Generating RSA key pair...');

            // Generate RSA key pair for digital signatures
            const rsaKeyPair = await CryptoModule.generateRSAKeyPair();
            const rsaPublicKey = await CryptoModule.exportPublicKey(rsaKeyPair.publicKey);
            const rsaPrivateKey = await CryptoModule.exportPrivateKey(rsaKeyPair.privateKey);

            if (onProgress) onProgress('Registering with server...');

            // Register with server
            const response = await fetch('/api/keys/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userId: userId,
                    password: password,
                    ecdhPublicKey: ecdhPublicKey,
                    rsaPublicKey: rsaPublicKey
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Registration failed');
            }

            if (onProgress) onProgress('Storing keys securely...');

            // Store private keys locally
            localStorage.setItem(ECDH_PRIVATE_KEY, ecdhPrivateKey);
            localStorage.setItem(RSA_PRIVATE_KEY, rsaPrivateKey);
            localStorage.setItem(USER_ID_KEY, userId);

            if (onProgress) onProgress('Registration complete!');

            return {
                success: true,
                userId: userId,
                keyFingerprint: await CryptoModule.calculateFingerprint(ecdhPublicKey)
            };
        } catch (error) {
            console.error('Registration error:', error);
            throw error;
        }
    }

    /**
     * Login user with password
     */
    async function login(userId, password) {
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId, password })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Login failed');
            }

            const data = await response.json();

            // Store session
            localStorage.setItem(TOKEN_KEY, data.token);
            localStorage.setItem(USER_ID_KEY, data.userId);

            return {
                success: true,
                token: data.token,
                userId: data.userId
            };
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    /**
     * Logout user
     */
    async function logout() {
        const token = getToken();
        if (token) {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token }
                });
            } catch (e) {
                console.error('Logout request failed:', e);
            }
        }

        // Clear all stored data
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_ID_KEY);
        // Keep private keys for future logins
    }

    /**
     * Validate current session
     */
    async function validateSession() {
        const token = getToken();
        if (!token) {
            return { valid: false };
        }

        try {
            const response = await fetch('/api/auth/validate', {
                headers: { 'Authorization': 'Bearer ' + token }
            });

            if (response.ok) {
                const data = await response.json();
                return { valid: true, user: data };
            }
        } catch (e) {
            console.error('Session validation failed:', e);
        }

        return { valid: false };
    }

    /**
     * Check if user is authenticated
     */
    function isAuthenticated() {
        return !!getToken() && !!getUserId();
    }

    /**
     * Get authentication token
     */
    function getToken() {
        return localStorage.getItem(TOKEN_KEY);
    }

    /**
     * Get current user ID
     */
    function getUserId() {
        return localStorage.getItem(USER_ID_KEY);
    }

    /**
     * Get stored ECDH private key
     */
    function getECDHPrivateKey() {
        return localStorage.getItem(ECDH_PRIVATE_KEY);
    }

    /**
     * Get stored RSA private key
     */
    function getRSAPrivateKey() {
        return localStorage.getItem(RSA_PRIVATE_KEY);
    }

    /**
     * Check if private keys exist
     */
    function hasPrivateKeys() {
        return !!getECDHPrivateKey() && !!getRSAPrivateKey();
    }

    /**
     * Regenerate and update keys
     */
    async function regenerateKeys(onProgress) {
        try {
            const token = getToken();
            const userId = getUserId();

            if (!token || !userId) {
                throw new Error('Not authenticated');
            }

            if (onProgress) onProgress('Generating new ECDH key pair...');

            // Generate new ECDH key pair
            const ecdhKeyPair = await CryptoModule.generateECDHKeyPair();
            const ecdhPublicKey = await CryptoModule.exportPublicKey(ecdhKeyPair.publicKey);
            const ecdhPrivateKey = await CryptoModule.exportPrivateKey(ecdhKeyPair.privateKey);

            if (onProgress) onProgress('Generating new RSA key pair...');

            // Generate new RSA key pair
            const rsaKeyPair = await CryptoModule.generateRSAKeyPair();
            const rsaPublicKey = await CryptoModule.exportPublicKey(rsaKeyPair.publicKey);
            const rsaPrivateKey = await CryptoModule.exportPrivateKey(rsaKeyPair.privateKey);

            if (onProgress) onProgress('Updating keys on server...');

            // Update on server
            const response = await fetch('/api/keys/' + userId + '/keys', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({
                    ecdhPublicKey: ecdhPublicKey,
                    rsaPublicKey: rsaPublicKey
                })
            });

            if (!response.ok) {
                throw new Error('Failed to update keys on server');
            }

            if (onProgress) onProgress('Storing new keys...');

            // Update local storage
            localStorage.setItem(ECDH_PRIVATE_KEY, ecdhPrivateKey);
            localStorage.setItem(RSA_PRIVATE_KEY, rsaPrivateKey);

            // Clear all session keys
            CryptoModule.clearAllSessionKeys();

            if (onProgress) onProgress('Keys regenerated successfully!');

            return {
                success: true,
                keyFingerprint: await CryptoModule.calculateFingerprint(ecdhPublicKey)
            };
        } catch (error) {
            console.error('Key regeneration error:', error);
            throw error;
        }
    }

    /**
     * Revoke current keys
     */
    async function revokeKeys(reason) {
        const token = getToken();
        const userId = getUserId();

        if (!token || !userId) {
            throw new Error('Not authenticated');
        }

        const response = await fetch('/api/revocation/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({
                userId: userId,
                reason: reason || 'User requested revocation'
            })
        });

        if (!response.ok) {
            throw new Error('Failed to revoke keys');
        }

        // Clear all local data
        localStorage.clear();

        return { success: true };
    }

    // Public API
    return {
        register,
        login,
        logout,
        validateSession,
        isAuthenticated,
        getToken,
        getUserId,
        getECDHPrivateKey,
        getRSAPrivateKey,
        hasPrivateKeys,
        regenerateKeys,
        revokeKeys
    };
})();

// Make globally available
window.AuthModule = AuthModule;
