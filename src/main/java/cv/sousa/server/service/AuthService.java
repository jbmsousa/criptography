package cv.sousa.server.service;

import cv.sousa.server.model.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class AuthService {

    @Inject
    UserService userService;

    @Inject
    TotpService totpService;

    @Inject
    RedisSessionService redisSessionService;

    // Fallback in-memory session storage (used when Redis is unavailable)
    private final Map<String, String> activeSessions = new ConcurrentHashMap<>();

    // Pending challenges for key verification
    private final Map<String, String> pendingChallenges = new ConcurrentHashMap<>();

    // Pending MFA sessions (password verified, awaiting MFA)
    private final Map<String, String> pendingMfaSessions = new ConcurrentHashMap<>();

    /**
     * Check if Redis session storage is available
     */
    private boolean useRedis() {
        return redisSessionService != null && redisSessionService.isRedisAvailable();
    }

    /**
     * Store session in Redis or fallback to in-memory
     */
    private void storeSession(String token, String userId) {
        if (useRedis()) {
            redisSessionService.storeSession(token, userId);
        } else {
            activeSessions.put(token, userId);
        }
    }

    /**
     * Remove session from Redis or in-memory
     */
    private String removeSession(String token) {
        if (useRedis()) {
            var userId = redisSessionService.validateSession(token);
            redisSessionService.invalidateSession(token);
            return userId.orElse(null);
        } else {
            return activeSessions.remove(token);
        }
    }

    /**
     * Login result containing authentication state
     */
    public record LoginResult(
        boolean success,
        String token,
        boolean mfaRequired,
        String mfaToken,
        String error
    ) {
        public static LoginResult success(String token) {
            return new LoginResult(true, token, false, null, null);
        }

        public static LoginResult mfaRequired(String mfaToken) {
            return new LoginResult(false, null, true, mfaToken, null);
        }

        public static LoginResult failure(String error) {
            return new LoginResult(false, null, false, null, error);
        }
    }

    @Transactional
    public LoginResult loginWithMfa(String userId, String password, String mfaCode) {
        // Verify password
        if (!userService.verifyPassword(userId, password)) {
            return LoginResult.failure("Invalid credentials");
        }

        User user = User.findByUserId(userId);
        if (user == null) {
            return LoginResult.failure("User not found");
        }

        // Check if MFA is enabled
        if (user.mfaEnabled) {
            if (mfaCode == null || mfaCode.isEmpty()) {
                // MFA required but not provided - create pending MFA session
                String mfaToken = generateSessionToken();
                pendingMfaSessions.put(mfaToken, userId);
                return LoginResult.mfaRequired(mfaToken);
            }

            // Verify MFA code
            if (!totpService.verifyMfa(user, mfaCode)) {
                return LoginResult.failure("Invalid MFA code");
            }
        }

        // Generate session token
        String token = generateSessionToken();
        storeSession(token, userId);

        // Update user status
        userService.setUserOnline(userId, true);
        userService.updateLastLogin(userId);

        return LoginResult.success(token);
    }

    /**
     * Complete MFA verification for pending session
     */
    @Transactional
    public LoginResult completeMfaLogin(String mfaToken, String mfaCode) {
        String userId = pendingMfaSessions.get(mfaToken);
        if (userId == null) {
            return LoginResult.failure("Invalid or expired MFA session");
        }

        User user = User.findByUserId(userId);
        if (user == null) {
            pendingMfaSessions.remove(mfaToken);
            return LoginResult.failure("User not found");
        }

        // Verify MFA code
        if (!totpService.verifyMfa(user, mfaCode)) {
            return LoginResult.failure("Invalid MFA code");
        }

        // Remove pending MFA session
        pendingMfaSessions.remove(mfaToken);

        // Generate session token
        String token = generateSessionToken();
        storeSession(token, userId);

        // Update user status
        userService.setUserOnline(userId, true);
        userService.updateLastLogin(userId);

        return LoginResult.success(token);
    }

    @Transactional
    public Optional<String> login(String userId, String password) {
        if (!userService.verifyPassword(userId, password)) {
            return Optional.empty();
        }

        // Generate session token
        String token = generateSessionToken();
        storeSession(token, userId);

        // Update user status
        userService.setUserOnline(userId, true);
        userService.updateLastLogin(userId);

        return Optional.of(token);
    }

    @Transactional
    public void logout(String token) {
        String userId = removeSession(token);
        if (userId != null) {
            userService.setUserOnline(userId, false);
        }
    }

    public Optional<String> validateSession(String token) {
        if (useRedis()) {
            return redisSessionService.validateSession(token);
        }
        return Optional.ofNullable(activeSessions.get(token));
    }

    public boolean isSessionValid(String token) {
        if (useRedis()) {
            return redisSessionService.isSessionValid(token);
        }
        return activeSessions.containsKey(token);
    }

    public Optional<User> getAuthenticatedUser(String token) {
        return validateSession(token).flatMap(userService::findByUserId);
    }

    /**
     * Generate challenge for key ownership verification
     */
    public String generateChallenge(String userId) {
        byte[] challengeBytes = new byte[32];
        new SecureRandom().nextBytes(challengeBytes);
        String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        pendingChallenges.put(userId, challenge);
        return challenge;
    }

    /**
     * Verify challenge response (signature) for key ownership
     */
    public boolean verifyChallengeResponse(String userId, String signedChallenge) {
        String challenge = pendingChallenges.remove(userId);
        if (challenge == null) {
            return false;
        }

        // Here we would verify the signature using the user's RSA public key
        // For now, this is a placeholder - actual verification happens client-side
        return userService.findByUserId(userId)
            .map(user -> verifySignature(challenge, signedChallenge, user.rsaPublicKey))
            .orElse(false);
    }

    private boolean verifySignature(String challenge, String signedChallenge, String rsaPublicKey) {
        // Signature verification implementation
        // In production, this would use RSA-SHA256 verification
        try {
            byte[] challengeBytes = Base64.getDecoder().decode(challenge);
            byte[] signatureBytes = Base64.getDecoder().decode(signedChallenge);
            byte[] publicKeyBytes = Base64.getDecoder().decode(rsaPublicKey);

            java.security.spec.X509EncodedKeySpec spec =
                new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.PublicKey publicKey = keyFactory.generatePublic(spec);

            java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(challengeBytes);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    private String generateSessionToken() {
        byte[] tokenBytes = new byte[32];
        new SecureRandom().nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    public void invalidateAllUserSessions(String userId) {
        if (useRedis()) {
            redisSessionService.invalidateAllUserSessions(userId);
        } else {
            activeSessions.entrySet().removeIf(entry -> entry.getValue().equals(userId));
        }
        userService.setUserOnline(userId, false);
    }

    /**
     * Get session statistics
     */
    public SessionStats getSessionStats() {
        if (useRedis()) {
            return new SessionStats(
                redisSessionService.getTotalSessionCount(),
                true,
                "redis"
            );
        }
        return new SessionStats(
            activeSessions.size(),
            false,
            "in-memory"
        );
    }

    public record SessionStats(long activeSessions, boolean persistent, String storageType) {}
}
