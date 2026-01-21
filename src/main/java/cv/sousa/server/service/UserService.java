package cv.sousa.server.service;

import cv.sousa.server.model.User;
import cv.sousa.server.repository.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.mindrot.jbcrypt.BCrypt;

import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserService {

    @Inject
    UserRepository userRepository;

    @Transactional
    public User registerUser(String userId, String password, String ecdhPublicKey, String rsaPublicKey) {
        if (userRepository.existsByUserId(userId)) {
            throw new IllegalArgumentException("User already exists: " + userId);
        }

        User user = new User();
        user.userId = userId;
        user.passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
        user.ecdhPublicKey = ecdhPublicKey;
        user.rsaPublicKey = rsaPublicKey;
        user.keyFingerprint = generateKeyFingerprint(ecdhPublicKey, rsaPublicKey);
        user.registeredAt = LocalDateTime.now();

        userRepository.persist(user);
        return user;
    }

    public Optional<User> findByUserId(String userId) {
        return userRepository.findByUserId(userId);
    }

    public boolean verifyPassword(String userId, String password) {
        return userRepository.findByUserId(userId)
            .map(user -> BCrypt.checkpw(password, user.passwordHash))
            .orElse(false);
    }

    public List<User> getAllUsers() {
        return userRepository.listAll();
    }

    public List<User> getAllUsersExcept(String userId) {
        return userRepository.findAllExcept(userId);
    }

    public List<User> getOnlineUsers() {
        return userRepository.findOnlineUsers();
    }

    @Transactional
    public void setUserOnline(String userId, boolean isOnline) {
        userRepository.updateOnlineStatus(userId, isOnline);
    }

    @Transactional
    public void updateLastLogin(String userId) {
        userRepository.updateLastLogin(userId);
    }

    @Transactional
    public void updateKeys(String userId, String ecdhPublicKey, String rsaPublicKey) {
        userRepository.findByUserId(userId).ifPresent(user -> {
            user.ecdhPublicKey = ecdhPublicKey;
            user.rsaPublicKey = rsaPublicKey;
            user.keyFingerprint = generateKeyFingerprint(ecdhPublicKey, rsaPublicKey);
        });
    }

    private String generateKeyFingerprint(String ecdhKey, String rsaKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ecdhKey.getBytes());
            digest.update(rsaKey.getBytes());
            byte[] hash = digest.digest();
            return Base64.getEncoder().encodeToString(hash).substring(0, 16);
        } catch (Exception e) {
            return "unknown";
        }
    }

    public boolean existsByUserId(String userId) {
        return userRepository.existsByUserId(userId);
    }
}
