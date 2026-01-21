package cv.sousa.server.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class User extends PanacheEntity {

    @Column(unique = true, nullable = false)
    public String userId;

    @Column(columnDefinition = "TEXT")
    public String ecdhPublicKey;

    @Column(columnDefinition = "TEXT")
    public String rsaPublicKey;

    @Column(nullable = false)
    public String passwordHash;

    public LocalDateTime registeredAt = LocalDateTime.now();

    public LocalDateTime lastLogin;

    @Column(nullable = false)
    public boolean isOnline = false;

    @Column(columnDefinition = "TEXT")
    public String keyFingerprint;

    public static User findByUserId(String userId) {
        return find("userId", userId).firstResult();
    }

    public static java.util.List<User> findOnlineUsers() {
        return list("isOnline", true);
    }
}
