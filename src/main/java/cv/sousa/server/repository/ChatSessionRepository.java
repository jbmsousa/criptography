package cv.sousa.server.repository;

import cv.sousa.server.model.ChatSession;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class ChatSessionRepository implements PanacheRepository<ChatSession> {

    public Optional<ChatSession> findBySessionId(String sessionId) {
        return find("sessionId", sessionId).firstResultOptional();
    }

    public Optional<ChatSession> findByParticipants(String user1, String user2) {
        return find("(user1Id = ?1 AND user2Id = ?2) OR (user1Id = ?2 AND user2Id = ?1)", user1, user2)
            .firstResultOptional();
    }

    public List<ChatSession> findActiveSessionsForUser(String userId) {
        return list("(user1Id = ?1 OR user2Id = ?1) AND active = true", userId);
    }

    public void updateActivity(String sessionId) {
        update("lastActivityAt = ?1 WHERE sessionId = ?2", LocalDateTime.now(), sessionId);
    }

    public void deactivateSession(String sessionId) {
        update("active = false WHERE sessionId = ?2", sessionId);
    }

    public void incrementKeyRotation(String sessionId) {
        update("keyRotatedAt = ?1, keyRotationCount = keyRotationCount + 1 WHERE sessionId = ?2",
            LocalDateTime.now(), sessionId);
    }

    public ChatSession createOrGetSession(String user1, String user2) {
        return findByParticipants(user1, user2).orElseGet(() -> {
            ChatSession session = new ChatSession();
            session.user1Id = user1;
            session.user2Id = user2;
            persist(session);
            return session;
        });
    }
}
