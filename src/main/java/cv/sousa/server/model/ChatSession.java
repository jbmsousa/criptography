package cv.sousa.server.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "chat_sessions", indexes = {
    @Index(name = "idx_participants", columnList = "user1Id, user2Id"),
    @Index(name = "idx_session_id", columnList = "sessionId", unique = true)
})
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class ChatSession extends PanacheEntity {

    @Column(unique = true, nullable = false)
    public String sessionId = UUID.randomUUID().toString();

    @Column(nullable = false)
    public String user1Id;

    @Column(nullable = false)
    public String user2Id;

    @Column(nullable = false)
    public LocalDateTime createdAt = LocalDateTime.now();

    public LocalDateTime lastActivityAt = LocalDateTime.now();

    @Column(nullable = false)
    public boolean active = true;

    public LocalDateTime keyRotatedAt;

    public int keyRotationCount = 0;

    public static ChatSession findBySessionId(String sessionId) {
        return find("sessionId", sessionId).firstResult();
    }

    public static ChatSession findByParticipants(String user1, String user2) {
        return find("(user1Id = ?1 AND user2Id = ?2) OR (user1Id = ?2 AND user2Id = ?1)", user1, user2).firstResult();
    }

    public static List<ChatSession> findActiveSessionsForUser(String userId) {
        return list("(user1Id = ?1 OR user2Id = ?1) AND active = true", userId);
    }

    public String getOtherParticipant(String currentUserId) {
        return currentUserId.equals(user1Id) ? user2Id : user1Id;
    }

    public boolean hasParticipant(String userId) {
        return user1Id.equals(userId) || user2Id.equals(userId);
    }

    public void updateActivity() {
        this.lastActivityAt = LocalDateTime.now();
    }

    public void rotateKey() {
        this.keyRotatedAt = LocalDateTime.now();
        this.keyRotationCount++;
    }
}
