package cv.sousa.client.service;

import cv.sousa.client.model.SecureMessage;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

/**
 * HTTP client service for server communication
 * Handles REST API calls for user management and messaging
 */
public class EnhancedMessagingService {

    private final HttpClient httpClient;
    private final String baseUrl;
    private String authToken;

    public EnhancedMessagingService(String baseUrl) {
        this.baseUrl = baseUrl;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    public EnhancedMessagingService(String baseUrl, HttpClient httpClient) {
        this.baseUrl = baseUrl;
        this.httpClient = httpClient;
    }

    public void setAuthToken(String token) {
        this.authToken = token;
    }

    /**
     * Register a new user with keys (legacy API for CLI client)
     */
    public void registerUser(String userId, String ecdhPublicKey, String rsaPublicKey) throws Exception {
        String json = String.format("""
            {
                "userId": "%s",
                "password": "defaultPassword123",
                "ecdhPublicKey": "%s",
                "rsaPublicKey": "%s"
            }
            """, userId, ecdhPublicKey, rsaPublicKey);

        HttpResponse<String> response = sendPost("/api/keys/register", json, false);

        if (response.statusCode() != 201 && response.statusCode() != 200) {
            throw new RuntimeException("Registration failed: " + response.body());
        }
    }

    /**
     * Register a new user with password
     */
    public RegistrationResult register(String userId, String password,
                                       String ecdhPublicKey, String rsaPublicKey) throws Exception {
        String json = String.format("""
            {
                "userId": "%s",
                "password": "%s",
                "ecdhPublicKey": "%s",
                "rsaPublicKey": "%s"
            }
            """, userId, password, ecdhPublicKey, rsaPublicKey);

        HttpResponse<String> response = sendPost("/api/keys/register", json, false);

        if (response.statusCode() == 201) {
            return new RegistrationResult(true, "Registration successful", userId);
        } else if (response.statusCode() == 409) {
            return new RegistrationResult(false, "User already exists", null);
        } else {
            return new RegistrationResult(false, "Registration failed: " + response.body(), null);
        }
    }

    /**
     * Login with credentials
     */
    public LoginResult login(String userId, String password) throws Exception {
        String json = String.format("""
            {
                "userId": "%s",
                "password": "%s"
            }
            """, userId, password);

        HttpResponse<String> response = sendPost("/api/auth/login", json, false);

        if (response.statusCode() == 200) {
            String body = response.body();
            String token = extractJsonField(body, "token");
            this.authToken = token;
            return new LoginResult(true, token, userId);
        } else {
            return new LoginResult(false, null, null);
        }
    }

    /**
     * Logout current session
     */
    public void logout() throws Exception {
        if (authToken != null) {
            sendPost("/api/auth/logout", "{}", true);
            authToken = null;
        }
    }

    /**
     * Get user's public keys as Map (legacy API)
     */
    public Map<String, Object> getUserKeys(String userId) throws Exception {
        HttpResponse<String> response = sendGet("/api/keys/" + userId);

        if (response.statusCode() == 200) {
            return parseJsonToMap(response.body());
        }
        throw new RuntimeException("User not found: " + userId);
    }

    /**
     * Get all registered users as List of Maps
     */
    public List<Map<String, Object>> listUsers() throws Exception {
        HttpResponse<String> response = sendGet("/api/keys/users");
        return parseJsonToList(response.body());
    }

    /**
     * Get all registered users as JSON string
     */
    public String getAllUsers() throws Exception {
        HttpResponse<String> response = sendGet("/api/keys/users");
        return response.body();
    }

    /**
     * Get online users
     */
    public String getOnlineUsers() throws Exception {
        HttpResponse<String> response = sendGet("/api/keys/users/online");
        return response.body();
    }

    /**
     * Check if a key is revoked
     */
    public boolean isKeyRevoked(String fingerprint) throws Exception {
        HttpResponse<String> response = sendGet("/api/revocation/check/" + fingerprint);
        return response.body().contains("\"revoked\":true");
    }

    /**
     * Revoke a key (legacy API)
     */
    public void revokeKey(String userId, String publicKey, String reason) throws Exception {
        String fingerprint = calculateFingerprint(publicKey);
        String json = String.format("""
            {
                "userId": "%s",
                "publicKey": "%s",
                "reason": "%s"
            }
            """, userId, publicKey, reason);

        HttpResponse<String> response = sendPost("/api/revocation/revoke", json, true);

        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw new RuntimeException("Revocation failed: " + response.body());
        }
    }

    /**
     * Get revocation statistics
     */
    public Map<String, Object> getRevocationStats() throws Exception {
        HttpResponse<String> response = sendGet("/api/revocation/stats");
        return parseJsonToMap(response.body());
    }

    /**
     * Store a message on the server
     */
    public void storeMessage(SecureMessage message) throws Exception {
        String json = String.format("""
            {
                "recipientId": "%s",
                "sessionId": "%s",
                "encryptedContent": "%s",
                "signature": "%s"
            }
            """,
            message.getRecipientId(),
            message.getSenderId() + "-" + message.getRecipientId(),
            Base64.getEncoder().encodeToString(message.getEncryptedContent()),
            Base64.getEncoder().encodeToString(message.getSignature())
        );

        sendPost("/api/messages", json, true);
    }

    /**
     * Get message history with a user
     */
    public String getMessageHistory(String otherUserId, int limit) throws Exception {
        HttpResponse<String> response = sendGet(
            "/api/messages/history/" + otherUserId + "?limit=" + limit);
        return response.body();
    }

    /**
     * Get unread message count
     */
    public long getUnreadCount() throws Exception {
        HttpResponse<String> response = sendGet("/api/messages/unread-count");
        String count = extractJsonField(response.body(), "count");
        return Long.parseLong(count);
    }

    /**
     * Calculate fingerprint for a public key
     */
    public String calculateFingerprint(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(keyBytes);
        return Base64.getEncoder().encodeToString(hash);
    }

    private HttpResponse<String> sendGet(String path) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .GET()
            .header("Content-Type", "application/json");

        if (authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> sendPost(String path, String json, boolean requireAuth) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .header("Content-Type", "application/json");

        if (requireAuth && authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String extractJsonField(String json, String field) {
        String searchKey = "\"" + field + "\":";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) return null;

        int valueStart = keyIndex + searchKey.length();
        while (valueStart < json.length() && json.charAt(valueStart) == ' ') valueStart++;

        if (valueStart >= json.length()) return null;

        if (json.charAt(valueStart) == '"') {
            int valueEnd = json.indexOf('"', valueStart + 1);
            if (valueEnd == -1) return null;
            return json.substring(valueStart + 1, valueEnd);
        } else {
            int valueEnd = valueStart;
            while (valueEnd < json.length() && json.charAt(valueEnd) != ',' && json.charAt(valueEnd) != '}') {
                valueEnd++;
            }
            return json.substring(valueStart, valueEnd).trim();
        }
    }

    private Map<String, Object> parseJsonToMap(String json) {
        Map<String, Object> map = new HashMap<>();
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1);
        if (json.endsWith("}")) json = json.substring(0, json.length() - 1);

        String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
        for (String pair : pairs) {
            String[] keyValue = pair.split(":", 2);
            if (keyValue.length == 2) {
                String key = keyValue[0].trim().replace("\"", "");
                String value = keyValue[1].trim();
                if (value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                map.put(key, value);
            }
        }
        return map;
    }

    private List<Map<String, Object>> parseJsonToList(String json) {
        List<Map<String, Object>> list = new ArrayList<>();
        json = json.trim();
        if (!json.startsWith("[")) return list;

        json = json.substring(1, json.length() - 1);
        int depth = 0;
        int start = 0;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            else if (c == ',' && depth == 0) {
                String obj = json.substring(start, i).trim();
                if (!obj.isEmpty()) {
                    list.add(parseJsonToMap(obj));
                }
                start = i + 1;
            }
        }
        String lastObj = json.substring(start).trim();
        if (!lastObj.isEmpty()) {
            list.add(parseJsonToMap(lastObj));
        }

        return list;
    }

    // Result classes
    public static class RegistrationResult {
        public final boolean success;
        public final String message;
        public final String userId;

        public RegistrationResult(boolean success, String message, String userId) {
            this.success = success;
            this.message = message;
            this.userId = userId;
        }
    }

    public static class LoginResult {
        public final boolean success;
        public final String token;
        public final String userId;

        public LoginResult(boolean success, String token, String userId) {
            this.success = success;
            this.token = token;
            this.userId = userId;
        }
    }

    public static class UserKeys {
        public final String userId;
        public final String ecdhPublicKey;
        public final String rsaPublicKey;
        public final String fingerprint;

        public UserKeys(String userId, String ecdhPublicKey, String rsaPublicKey, String fingerprint) {
            this.userId = userId;
            this.ecdhPublicKey = ecdhPublicKey;
            this.rsaPublicKey = rsaPublicKey;
            this.fingerprint = fingerprint;
        }
    }
}
