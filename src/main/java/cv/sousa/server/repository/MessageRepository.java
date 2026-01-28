package cv.sousa.server.repository;

import cv.sousa.server.model.Message;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.LocalDateTime;
import java.util.List;

@ApplicationScoped
public class MessageRepository implements PanacheRepository<Message> {

    public List<Message> findBySession(String sessionId) {
        return list("sessionId", sessionId);
    }

    public List<Message> findBetweenUsers(String user1, String user2) {
        return list("(senderId = ?1 AND recipientId = ?2) OR (senderId = ?2 AND recipientId = ?1) ORDER BY sentAt ASC",
            user1, user2);
    }

    public List<Message> findUndeliveredForUser(String userId) {
        return list("recipientId = ?1 AND delivered = false ORDER BY sentAt ASC", userId);
    }

    public long countUnreadForUser(String userId) {
        return count("recipientId = ?1 AND read = false", userId);
    }

    public void markAsDelivered(Long messageId) {
        update("delivered = true, deliveredAt = ?1 WHERE id = ?2", LocalDateTime.now(), messageId);
    }

    public void markAsRead(Long messageId) {
        update("read = true, readAt = ?1 WHERE id = ?2", LocalDateTime.now(), messageId);
    }

    public void markAllAsReadBetweenUsers(String senderId, String recipientId) {
        update("read = true, readAt = ?1 WHERE senderId = ?2 AND recipientId = ?3 AND read = false",
            LocalDateTime.now(), senderId, recipientId);
    }

    public List<Message> findRecentMessages(String user1, String user2, int limit) {
        // Get most recent messages (DESC), then reverse to chronological order (ASC)
        List<Message> messages = find("(senderId = ?1 AND recipientId = ?2) OR (senderId = ?2 AND recipientId = ?1) ORDER BY sentAt DESC",
            user1, user2).page(0, limit).list();
        java.util.Collections.reverse(messages);
        return messages;
    }
}
