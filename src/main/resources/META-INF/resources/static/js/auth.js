/**
 * Secure Messaging - Authentication Module
 * Handles user registration, login, and session management
 * Uses SecureStorage for encrypted key storage
 */

const AuthModule = (function() {
    'use strict';

    // Legacy localStorage keys (for migration)
    const LEGACY_TOKEN_KEY = 'authToken';
    const LEGACY_USER_ID_KEY = 'userId';
    const LEGACY_ECDH_PRIVATE_KEY = 'ecdhPrivateKey';
    const LEGACY_RSA_PRIVATE_KEY = 'rsaPrivateKey';

    // Track if secure storage is initialized
    let secureStorageReady = false;

    /**
     * Initialize secure storage with user password
     * @param {string} password - User password for key derivation
     * @param {boolean} isNewUser - Whether this is a new user registration
     */
    async function initializeSecureStorage(password, isNewUser = false) {
        try {
            await SecureStorage.initialize(password, isNewUser);
            secureStorageReady = true;

            // Check for legacy keys that need migration
            if (!isNewUser && SecureStorage.hasLegacyKeys()) {
                const userId = SecureStorage.getUserId() || localStorage.getItem(LEGACY_USER_ID_KEY);
                if (userId) {
                    console.log('Migrating keys from localStorage to secure storage...');
                    await SecureStorage.migrateFromLocalStorage(userId);
                }
            }

            return true;
        } catch (error) {
            console.error('Failed to initialize secure storage:', error);
            secureStorageReady = false;
            throw error;
        }
    }

    /**
     * Check if secure storage is ready
     */
    function isSecureStorageReady() {
        return secureStorageReady && SecureStorage.isStorageInitialized();
    }

    /**
     * Register new user with generated key pairs
     */
    async function register(userId, nome, email, password, onProgress) {
        try {
            if (onProgress) onProgress('Validating input...');

            if (!userId || userId.length < 3) {
                throw new Error('User ID must be at least 3 characters');
            }
            if (!password || password.length < 8) {
                throw new Error('Password must be at least 8 characters');
            }

            // Initialize secure storage for new user
            if (onProgress) onProgress('Initializing secure storage...');
            await initializeSecureStorage(password, true);

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
                    nome: nome,
                    email: email,
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

            // Store private keys in secure storage
            await SecureStorage.setECDHPrivateKey(ecdhPrivateKey, userId);
            await SecureStorage.setRSAPrivateKey(rsaPrivateKey, userId);
            SecureStorage.setUserId(userId);

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
            // Initialize secure storage with password
            await initializeSecureStorage(password, false);

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

            // Store session token securely
            await SecureStorage.setAuthToken(data.token, userId);
            SecureStorage.setUserId(data.userId);

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
        const token = await getToken();
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

        // Clear session data but keep private keys for future logins
        await SecureStorage.deleteAuthToken();
        SecureStorage.deleteUserId();

        // Also clear legacy localStorage data
        localStorage.removeItem(LEGACY_TOKEN_KEY);
        localStorage.removeItem(LEGACY_USER_ID_KEY);
    }

    /**
     * Validate current session
     */
    async function validateSession() {
        const token = await getToken();
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
    async function isAuthenticated() {
        const token = await getToken();
        const userId = getUserId();
        return !!token && !!userId;
    }

    /**
     * Get authentication token
     */
    async function getToken() {
        if (isSecureStorageReady()) {
            return await SecureStorage.getAuthToken();
        }
        // Fallback to legacy localStorage
        return localStorage.getItem(LEGACY_TOKEN_KEY);
    }

    /**
     * Get current user ID
     */
    function getUserId() {
        return SecureStorage.getUserId() || localStorage.getItem(LEGACY_USER_ID_KEY);
    }

    /**
     * Get stored ECDH private key
     */
    async function getECDHPrivateKey() {
        if (isSecureStorageReady()) {
            return await SecureStorage.getECDHPrivateKey();
        }
        // Fallback to legacy localStorage
        return localStorage.getItem(LEGACY_ECDH_PRIVATE_KEY);
    }

    /**
     * Get stored RSA private key
     */
    async function getRSAPrivateKey() {
        if (isSecureStorageReady()) {
            return await SecureStorage.getRSAPrivateKey();
        }
        // Fallback to legacy localStorage
        return localStorage.getItem(LEGACY_RSA_PRIVATE_KEY);
    }

    /**
     * Check if private keys exist
     */
    async function hasPrivateKeys() {
        const ecdh = await getECDHPrivateKey();
        const rsa = await getRSAPrivateKey();
        return !!ecdh && !!rsa;
    }

    /**
     * Check for legacy keys in localStorage (not yet migrated)
     */
    function hasLegacyKeys() {
        return SecureStorage.hasLegacyKeys() ||
            !!(localStorage.getItem(LEGACY_ECDH_PRIVATE_KEY) ||
               localStorage.getItem(LEGACY_RSA_PRIVATE_KEY));
    }

    /**
     * Regenerate and update keys
     */
    async function regenerateKeys(onProgress) {
        try {
            const token = await getToken();
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

            if (onProgress) onProgress('Storing new keys securely...');

            // Update secure storage
            await SecureStorage.setECDHPrivateKey(ecdhPrivateKey, userId);
            await SecureStorage.setRSAPrivateKey(rsaPrivateKey, userId);

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
        const token = await getToken();
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

        // Clear all secure storage data
        await SecureStorage.clearAll();

        // Also clear legacy localStorage
        localStorage.clear();

        return { success: true };
    }

    /**
     * Create encrypted backup of keys
     * @param {string} backupPassword - Password to encrypt backup
     */
    async function createKeyBackup(backupPassword) {
        if (!isSecureStorageReady()) {
            throw new Error('Secure storage not initialized');
        }
        return await SecureStorage.createBackup(backupPassword);
    }

    /**
     * Restore keys from encrypted backup
     * @param {string} backupData - Base64 encoded encrypted backup
     * @param {string} backupPassword - Password to decrypt backup
     */
    async function restoreKeyBackup(backupData, backupPassword) {
        return await SecureStorage.restoreBackup(backupData, backupPassword);
    }

    /**
     * Re-initialize secure storage (e.g., after page refresh)
     * Requires user to re-enter password
     */
    async function unlockStorage(password) {
        return await initializeSecureStorage(password, false);
    }

    /**
     * Check if storage needs to be unlocked
     */
    function needsUnlock() {
        return !isSecureStorageReady() && (SecureStorage.hasLegacyKeys() ||
            !!(localStorage.getItem(LEGACY_ECDH_PRIVATE_KEY)));
    }

    // Public API
    return {
        // Authentication
        register,
        login,
        logout,
        validateSession,
        isAuthenticated,
        getToken,
        getUserId,

        // Key management
        getECDHPrivateKey,
        getRSAPrivateKey,
        hasPrivateKeys,
        hasLegacyKeys,
        regenerateKeys,
        revokeKeys,

        // Secure storage
        initializeSecureStorage,
        isSecureStorageReady,
        unlockStorage,
        needsUnlock,

        // Backup/Restore
        createKeyBackup,
        restoreKeyBackup
    };
})();

// Make globally available
window.AuthModule = AuthModule;
