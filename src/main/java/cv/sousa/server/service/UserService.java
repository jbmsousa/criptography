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

    /**
     * Validates a Portuguese NIF (Número de Identificação Fiscal)
     * @param nif The NIF to validate (9 digits)
     * @return true if valid, false otherwise
     */
    public boolean isValidNIF(String nif) {
        if (nif == null || !nif.matches("\\d{9}")) {
            return false;
        }

        // First digit cannot be 0 or 4
        int firstDigit = Character.getNumericValue(nif.charAt(0));
        if (firstDigit == 0 || firstDigit == 4) {
            return false;
        }

        // Calculate checksum using modulo 11
        int sum = 0;
        for (int i = 0; i < 8; i++) {
            sum += Character.getNumericValue(nif.charAt(i)) * (9 - i);
        }

        int checkDigit = 11 - (sum % 11);
        int expectedDigit = checkDigit >= 10 ? 0 : checkDigit;
        int actualDigit = Character.getNumericValue(nif.charAt(8));

        return expectedDigit == actualDigit;
    }

    @Transactional
    public User registerUser(String nif, String nome, String email, String password, String ecdhPublicKey, String rsaPublicKey) {
        // Validate NIF format
        if (!isValidNIF(nif)) {
            throw new IllegalArgumentException("NIF invalido: " + nif);
        }

        // Validate nome
        if (nome == null || nome.trim().length() < 3) {
            throw new IllegalArgumentException("Nome deve ter pelo menos 3 caracteres");
        }

        // Validate email
        if (email == null || !email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new IllegalArgumentException("Email invalido");
        }

        if (userRepository.existsByNif(nif)) {
            throw new IllegalArgumentException("Utilizador ja existe com este NIF: " + nif);
        }

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Utilizador ja existe com este email: " + email);
        }

        User user = new User();
        user.nif = nif;
        user.nome = nome.trim();
        user.email = email.toLowerCase().trim();
        user.passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
        user.ecdhPublicKey = ecdhPublicKey;
        user.rsaPublicKey = rsaPublicKey;
        user.keyFingerprint = generateKeyFingerprint(ecdhPublicKey, rsaPublicKey);
        user.registeredAt = LocalDateTime.now();

        userRepository.persist(user);
        return user;
    }

    // Backward compatibility - will be removed in future version
    @Transactional
    @Deprecated
    public User registerUser(String userId, String password, String ecdhPublicKey, String rsaPublicKey) {
        return registerUser(userId, "Utilizador " + userId, userId + "@temp.com", password, ecdhPublicKey, rsaPublicKey);
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
    public void setAllUsersOffline() {
        userRepository.setAllUsersOffline();
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
