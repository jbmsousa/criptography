package cv.sousa.server.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "messages", indexes = {
    @Index(name = "idx_sender", columnList = "senderId"),
    @Index(name = "idx_recipient", columnList = "recipientId"),
    @Index(name = "idx_session", columnList = "sessionId")
})
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Message extends PanacheEntity {

    @Column(nullable = false)
    public String senderId;

    @Column(nullable = false)
    public String recipientId;

    @Column(columnDefinition = "TEXT", nullable = false)
    public String encryptedContent;

    @Column(columnDefinition = "TEXT")
    public String senderEncryptedContent;

    @Column(columnDefinition = "TEXT")
    public String signature;

    public String sessionId;

    // Double Ratchet header fields
    @Column(columnDefinition = "TEXT")
    public String ratchetDhPublicKey;  // Sender's current DH public key

    public Integer ratchetPreviousChainLength;  // Length of previous sending chain

    public Integer ratchetMessageNumber;  // Message number in current chain

    @Column(nullable = false)
    public LocalDateTime sentAt = LocalDateTime.now();

    public boolean delivered = false;

    public LocalDateTime deliveredAt;

    public boolean read = false;

    public LocalDateTime readAt;

    public static List<Message> findBySession(String sessionId) {
        return list("sessionId", sessionId);
    }

    public static List<Message> findBetweenUsers(String user1, String user2) {
        return list("(senderId = ?1 AND recipientId = ?2) OR (senderId = ?2 AND recipientId = ?1)",
            user1, user2);
    }

    public static List<Message> findUndeliveredForUser(String userId) {
        return list("recipientId = ?1 AND delivered = false", userId);
    }

    public static long countUnreadForUser(String userId) {
        return count("recipientId = ?1 AND read = false", userId);
    }
}
