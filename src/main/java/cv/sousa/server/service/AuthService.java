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

    // Session tokens mapped to user IDs
    private final Map<String, String> activeSessions = new ConcurrentHashMap<>();

    // Pending challenges for key verification
    private final Map<String, String> pendingChallenges = new ConcurrentHashMap<>();

    @Transactional
    public Optional<String> login(String userId, String password) {
        if (!userService.verifyPassword(userId, password)) {
            return Optional.empty();
        }

        // Generate session token
        String token = generateSessionToken();
        activeSessions.put(token, userId);

        // Update user status
        userService.setUserOnline(userId, true);
        userService.updateLastLogin(userId);

        return Optional.of(token);
    }

    @Transactional
    public void logout(String token) {
        String userId = activeSessions.remove(token);
        if (userId != null) {
            userService.setUserOnline(userId, false);
        }
    }

    public Optional<String> validateSession(String token) {
        return Optional.ofNullable(activeSessions.get(token));
    }

    public boolean isSessionValid(String token) {
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
        activeSessions.entrySet().removeIf(entry -> entry.getValue().equals(userId));
        userService.setUserOnline(userId, false);
    }
}
