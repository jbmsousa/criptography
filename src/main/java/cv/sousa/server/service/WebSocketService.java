package cv.sousa.server.service;

import cv.sousa.server.model.ChatSession;
import cv.sousa.server.repository.ChatSessionRepository;
import cv.sousa.server.websocket.ChatWebSocket;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class WebSocketService {

    @Inject
    ChatSessionRepository chatSessionRepository;

    @Inject
    UserService userService;

    // Track active session keys for rotation
    private final Map<String, SessionKeyState> sessionKeyStates = new ConcurrentHashMap<>();

    private static final long KEY_ROTATION_INTERVAL_MS = 300000; // 5 minutes

    @Transactional
    public ChatSession getOrCreateSession(String user1, String user2) {
        return chatSessionRepository.createOrGetSession(user1, user2);
    }

    @Transactional
    public void updateSessionActivity(String sessionId) {
        chatSessionRepository.updateActivity(sessionId);
    }

    public boolean shouldRotateKey(String sessionId) {
        SessionKeyState state = sessionKeyStates.get(sessionId);
        if (state == null) {
            return true;
        }
        return System.currentTimeMillis() - state.createdAt > KEY_ROTATION_INTERVAL_MS;
    }

    public void markKeyRotated(String sessionId) {
        sessionKeyStates.put(sessionId, new SessionKeyState(System.currentTimeMillis()));
        chatSessionRepository.incrementKeyRotation(sessionId);
    }

    public void notifyKeyRotation(String sessionId, String userId, String newPublicKey, String salt) {
        chatSessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            String otherUser = session.getOtherParticipant(userId);
            if (ChatWebSocket.isUserOnline(otherUser)) {
                String message = String.format(
                    "{\"type\":\"key_rotation\",\"sessionId\":\"%s\",\"senderId\":\"%s\",\"publicKey\":\"%s\",\"salt\":\"%s\"}",
                    sessionId, userId, newPublicKey, salt
                );
                ChatWebSocket.broadcastToUser(otherUser, message);
            }
        });
    }

    public void notifyUserStatusChange(String userId, boolean isOnline) {
        List<ChatSession> sessions = chatSessionRepository.findActiveSessionsForUser(userId);
        for (ChatSession session : sessions) {
            String otherUser = session.getOtherParticipant(userId);
            if (ChatWebSocket.isUserOnline(otherUser)) {
                String message = String.format(
                    "{\"type\":\"user_status\",\"userId\":\"%s\",\"isOnline\":%s}",
                    userId, isOnline
                );
                ChatWebSocket.broadcastToUser(otherUser, message);
            }
        }
    }

    public List<String> getOnlineUsersInSession(String sessionId) {
        return chatSessionRepository.findBySessionId(sessionId)
            .map(session -> {
                List<String> online = new ArrayList<>();
                if (ChatWebSocket.isUserOnline(session.user1Id)) {
                    online.add(session.user1Id);
                }
                if (ChatWebSocket.isUserOnline(session.user2Id)) {
                    online.add(session.user2Id);
                }
                return online;
            })
            .orElse(Collections.emptyList());
    }

    public boolean isUserOnline(String userId) {
        return ChatWebSocket.isUserOnline(userId);
    }

    public void sendDirectMessage(String userId, String jsonMessage) {
        ChatWebSocket.broadcastToUser(userId, jsonMessage);
    }

    private static class SessionKeyState {
        final long createdAt;

        SessionKeyState(long createdAt) {
            this.createdAt = createdAt;
        }
    }
}
