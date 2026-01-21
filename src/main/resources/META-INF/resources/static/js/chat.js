/**
 * Secure Messaging - Chat Module
 * Handles WebSocket communication and encrypted messaging
 */

const ChatModule = (function() {
    'use strict';

    let ws = null;
    let reconnectAttempts = 0;
    const MAX_RECONNECT_ATTEMPTS = 5;
    const RECONNECT_DELAY_MS = 5000;

    let authToken = null;
    let currentUserId = null;
    let chatPartnerId = null;
    let sessionKey = null;
    let partnerPublicKey = null;

    const messageHandlers = new Map();
    const pendingMessages = [];

    /**
     * Initialize chat module
     */
    async function initialize(config) {
        authToken = config.authToken || localStorage.getItem('authToken');
        currentUserId = config.userId || localStorage.getItem('userId');
        chatPartnerId = config.chatPartnerId;

        if (!authToken || !currentUserId) {
            throw new Error('Authentication required');
        }

        // Load partner's public key
        await loadPartnerPublicKey();

        // Derive session key
        await deriveSessionKeyForChat();

        // Connect WebSocket
        connectWebSocket();
    }

    /**
     * Load chat partner's public key from server
     */
    async function loadPartnerPublicKey() {
        if (!chatPartnerId) return;

        const response = await fetch('/api/keys/' + chatPartnerId);
        if (!response.ok) {
            throw new Error('Failed to load partner public key');
        }

        const userData = await response.json();
        partnerPublicKey = userData.ecdhPublicKey;

        console.log('Partner public key loaded:', chatPartnerId);
    }

    /**
     * Derive session key for current chat
     */
    async function deriveSessionKeyForChat() {
        if (!partnerPublicKey) return;

        const myPrivateKey = localStorage.getItem('ecdhPrivateKey');
        if (!myPrivateKey) {
            throw new Error('Private key not found');
        }

        const sessionId = getSessionId();
        sessionKey = await CryptoModule.getSessionKey(sessionId, myPrivateKey, partnerPublicKey);

        console.log('Session key derived for:', sessionId);
    }

    /**
     * Generate consistent session ID for two users
     */
    function getSessionId() {
        const users = [currentUserId, chatPartnerId].sort();
        return users.join('-');
    }

    /**
     * Connect to WebSocket server
     */
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = protocol + '//' + window.location.host + '/chat';

        ws = new WebSocket(wsUrl);

        ws.onopen = handleOpen;
        ws.onmessage = handleMessage;
        ws.onclose = handleClose;
        ws.onerror = handleError;
    }

    /**
     * Handle WebSocket connection open
     */
    function handleOpen() {
        console.log('WebSocket connected');
        reconnectAttempts = 0;

        // Authenticate
        sendRaw({
            type: 'auth',
            token: authToken
        });
    }

    /**
     * Handle incoming WebSocket messages
     */
    async function handleMessage(event) {
        try {
            const msg = JSON.parse(event.data);

            switch (msg.type) {
                case 'auth_success':
                    handleAuthSuccess(msg);
                    break;
                case 'message':
                    await handleIncomingMessage(msg);
                    break;
                case 'typing':
                    handleTypingIndicator(msg);
                    break;
                case 'delivered':
                    handleDeliveryConfirmation(msg);
                    break;
                case 'read':
                    handleReadConfirmation(msg);
                    break;
                case 'user_status':
                    handleUserStatus(msg);
                    break;
                case 'key_rotation':
                    await handleKeyRotation(msg);
                    break;
                case 'error':
                    handleError(msg);
                    break;
            }

            // Call registered handlers
            const handlers = messageHandlers.get(msg.type) || [];
            handlers.forEach(handler => handler(msg));
        } catch (e) {
            console.error('Error handling message:', e);
        }
    }

    /**
     * Handle successful authentication
     */
    function handleAuthSuccess(msg) {
        console.log('Authenticated as:', msg.userId);
        triggerEvent('authenticated', msg);

        // Send any pending messages
        while (pendingMessages.length > 0) {
            const pending = pendingMessages.shift();
            sendRaw(pending);
        }
    }

    /**
     * Handle incoming encrypted message
     */
    async function handleIncomingMessage(msg) {
        if (msg.senderId !== chatPartnerId) {
            triggerEvent('message_from_other', msg);
            return;
        }

        try {
            const encryptedData = JSON.parse(msg.encryptedContent);

            // Check for replay attack
            if (CryptoModule.isReplayAttack(encryptedData.timestamp)) {
                console.warn('Possible replay attack detected');
                return;
            }

            // Decrypt message
            const plaintext = await CryptoModule.decryptMessage(encryptedData, sessionKey);

            // Verify signature if present
            if (msg.signature && partnerPublicKey) {
                const rsaPublicKey = await loadPartnerRSAKey();
                if (rsaPublicKey) {
                    const sigData = JSON.parse(msg.signature);
                    const isValid = await CryptoModule.verifySignature(
                        encryptedData.ciphertext,
                        sigData.signature,
                        sigData.timestamp,
                        rsaPublicKey
                    );
                    if (!isValid) {
                        console.warn('Invalid message signature');
                    }
                }
            }

            triggerEvent('message', {
                ...msg,
                decryptedContent: plaintext
            });

            // Send read acknowledgment
            sendAcknowledgment(msg.id, msg.senderId);
        } catch (e) {
            console.error('Failed to process message:', e);
            triggerEvent('message_error', { error: e.message, originalMessage: msg });
        }
    }

    /**
     * Load partner's RSA public key for signature verification
     */
    async function loadPartnerRSAKey() {
        try {
            const response = await fetch('/api/keys/' + chatPartnerId);
            if (response.ok) {
                const userData = await response.json();
                return userData.rsaPublicKey;
            }
        } catch (e) {
            console.error('Failed to load partner RSA key:', e);
        }
        return null;
    }

    /**
     * Handle typing indicator
     */
    function handleTypingIndicator(msg) {
        if (msg.senderId === chatPartnerId) {
            triggerEvent('typing', { isTyping: msg.isTyping });
        }
    }

    /**
     * Handle delivery confirmation
     */
    function handleDeliveryConfirmation(msg) {
        triggerEvent('delivered', msg);
    }

    /**
     * Handle read confirmation
     */
    function handleReadConfirmation(msg) {
        triggerEvent('read', msg);
    }

    /**
     * Handle user status change
     */
    function handleUserStatus(msg) {
        triggerEvent('user_status', msg);
    }

    /**
     * Handle key rotation request
     */
    async function handleKeyRotation(msg) {
        if (msg.senderId === chatPartnerId) {
            console.log('Key rotation from partner');
            CryptoModule.clearSessionKey(getSessionId());
            partnerPublicKey = msg.publicKey;
            await deriveSessionKeyForChat();
            triggerEvent('key_rotated', msg);
        }
    }

    /**
     * Handle WebSocket close
     */
    function handleClose(event) {
        console.log('WebSocket closed:', event.code, event.reason);
        triggerEvent('disconnected', { code: event.code, reason: event.reason });

        // Attempt reconnection
        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
            reconnectAttempts++;
            setTimeout(connectWebSocket, RECONNECT_DELAY_MS);
        } else {
            triggerEvent('connection_failed', { attempts: reconnectAttempts });
        }
    }

    /**
     * Handle WebSocket error
     */
    function handleError(error) {
        console.error('WebSocket error:', error);
        triggerEvent('error', { error: error.message || 'WebSocket error' });
    }

    /**
     * Send encrypted message
     */
    async function sendMessage(content) {
        if (!sessionKey) {
            throw new Error('Session key not established');
        }

        // Encrypt message
        const encryptedData = await CryptoModule.encryptMessage(content, sessionKey);

        // Sign the ciphertext
        const rsaPrivateKey = localStorage.getItem('rsaPrivateKey');
        let signature = null;
        if (rsaPrivateKey) {
            signature = await CryptoModule.signMessage(encryptedData.ciphertext, rsaPrivateKey);
        }

        const message = {
            type: 'message',
            recipientId: chatPartnerId,
            sessionId: getSessionId(),
            encryptedContent: JSON.stringify(encryptedData),
            signature: signature ? JSON.stringify(signature) : null
        };

        if (isConnected()) {
            sendRaw(message);
        } else {
            pendingMessages.push(message);
        }

        return encryptedData;
    }

    /**
     * Send typing indicator
     */
    function sendTypingIndicator(isTyping) {
        if (!isConnected()) return;

        sendRaw({
            type: 'typing',
            recipientId: chatPartnerId,
            isTyping: isTyping
        });
    }

    /**
     * Send read acknowledgment
     */
    function sendAcknowledgment(messageId, senderId) {
        if (!isConnected()) return;

        sendRaw({
            type: 'ack',
            messageId: messageId.toString(),
            senderId: senderId
        });
    }

    /**
     * Initiate key exchange
     */
    async function initiateKeyExchange() {
        const keyPair = await CryptoModule.generateECDHKeyPair();
        const publicKeyB64 = await CryptoModule.exportPublicKey(keyPair.publicKey);
        const salt = CryptoModule.generateSalt();

        sendRaw({
            type: 'key_exchange',
            recipientId: chatPartnerId,
            sessionId: getSessionId(),
            publicKey: publicKeyB64,
            salt: salt
        });

        return { keyPair, salt };
    }

    /**
     * Send raw message to WebSocket
     */
    function sendRaw(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(data));
        }
    }

    /**
     * Check if WebSocket is connected
     */
    function isConnected() {
        return ws && ws.readyState === WebSocket.OPEN;
    }

    /**
     * Register event handler
     */
    function on(event, handler) {
        if (!messageHandlers.has(event)) {
            messageHandlers.set(event, []);
        }
        messageHandlers.get(event).push(handler);
    }

    /**
     * Remove event handler
     */
    function off(event, handler) {
        if (messageHandlers.has(event)) {
            const handlers = messageHandlers.get(event);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }

    /**
     * Trigger event
     */
    function triggerEvent(event, data) {
        const handlers = messageHandlers.get(event) || [];
        handlers.forEach(handler => {
            try {
                handler(data);
            } catch (e) {
                console.error('Error in event handler:', e);
            }
        });
    }

    /**
     * Disconnect WebSocket
     */
    function disconnect() {
        if (ws) {
            ws.close();
            ws = null;
        }
        CryptoModule.clearAllSessionKeys();
    }

    // Public API
    return {
        initialize,
        sendMessage,
        sendTypingIndicator,
        initiateKeyExchange,
        isConnected,
        on,
        off,
        disconnect
    };
})();

// Make globally available
window.ChatModule = ChatModule;
