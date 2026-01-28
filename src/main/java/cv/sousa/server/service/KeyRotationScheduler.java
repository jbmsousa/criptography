package cv.sousa.server.service;

import cv.sousa.server.model.AuditAction;
import cv.sousa.server.model.ChatSession;
import cv.sousa.server.repository.ChatSessionRepository;
import cv.sousa.server.websocket.ChatWebSocket;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.List;
import org.jboss.logging.Logger;

/**
 * Scheduler service for automatic key rotation
 * Checks every minute for sessions that need key rotation (older than 5
 * minutes)
 */
@ApplicationScoped
public class KeyRotationScheduler {

    private static final Logger LOG = Logger.getLogger(KeyRotationScheduler.class);
    private static final int KEY_ROTATION_INTERVAL_MINUTES = 5;

    @Inject
    ChatSessionRepository chatSessionRepository;

    @Inject
    WebSocketService webSocketService;

    @Inject
    AuditService auditService;

    /**
     * Scheduled task that runs every minute to check for sessions needing key
     * rotation
     */
    @Scheduled(every = "1m", identity = "key-rotation-check")
    @Transactional
    public void checkAndRotateKeys() {
        LOG.debug("Checking for sessions needing key rotation...");

        LocalDateTime threshold = LocalDateTime.now().minusMinutes(KEY_ROTATION_INTERVAL_MINUTES);
        List<ChatSession> sessionsNeedingRotation = chatSessionRepository.findSessionsNeedingRotation(threshold);

        if (sessionsNeedingRotation.isEmpty()) {
            LOG.debug("No sessions need key rotation at this time");
            return;
        }

        LOG.info("Found " + sessionsNeedingRotation.size() + " session(s) needing key rotation");

        for (ChatSession session : sessionsNeedingRotation) {
            try {
                rotateSessionKey(session);
            } catch (Exception e) {
                LOG.error("Failed to rotate key for session " + session.sessionId, e);
            }
        }
    }

    /**
     * Rotate key for a specific session
     */
    private void rotateSessionKey(ChatSession session) {
        // Check if both users are online
        boolean user1Online = ChatWebSocket.isUserOnline(session.user1Id);
        boolean user2Online = ChatWebSocket.isUserOnline(session.user2Id);

        if (!user1Online && !user2Online) {
            LOG.debug("Skipping rotation for session " + session.sessionId + " - no users online");
            return;
        }

        LOG.info("Rotating key for session: " + session.sessionId +
                " (user1=" + session.user1Id + " online=" + user1Online +
                ", user2=" + session.user2Id + " online=" + user2Online + ")");

        // Mark key as rotated in database
        chatSessionRepository.incrementKeyRotation(session.sessionId);
        webSocketService.markKeyRotated(session.sessionId);

        // Notify online users to regenerate their session keys
        String rotationMessage = String.format(
                "{\"type\":\"key_rotation\",\"sessionId\":\"%s\",\"message\":\"Session key expired - please regenerate\"}",
                session.sessionId);

        if (user1Online) {
            ChatWebSocket.broadcastToUser(session.user1Id, rotationMessage);
            auditService.log(session.user1Id, AuditAction.KEY_ROTATED,
                    "Automatic key rotation for session " + session.sessionId);
        }

        if (user2Online) {
            ChatWebSocket.broadcastToUser(session.user2Id, rotationMessage);
            auditService.log(session.user2Id, AuditAction.KEY_ROTATED,
                    "Automatic key rotation for session " + session.sessionId);
        }

        LOG.info("Key rotation completed for session: " + session.sessionId +
                " (rotation count: " + (session.keyRotationCount + 1) + ")");
    }

    /**
     * Force key rotation for a specific session (can be called manually)
     */
    @Transactional
    public void forceRotation(String sessionId) {
        chatSessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            LOG.info("Forcing key rotation for session: " + sessionId);
            rotateSessionKey(session);
        });
    }
}
