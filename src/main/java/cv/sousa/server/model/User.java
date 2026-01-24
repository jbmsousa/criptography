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
    public String nif;

    @Column(nullable = false)
    public String nome;

    @Column(unique = true, nullable = false)
    public String email;

    // Keep userId as alias for nif for backward compatibility
    @Transient
    public String getUserId() {
        return nif;
    }

    @Transient
    public void setUserId(String userId) {
        this.nif = userId;
    }

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

    public static User findByUserId(String nif) {
        return find("nif", nif).firstResult();
    }

    public static User findByNif(String nif) {
        return find("nif", nif).firstResult();
    }

    public static User findByEmail(String email) {
        return find("email", email).firstResult();
    }

    public static java.util.List<User> findOnlineUsers() {
        return list("isOnline", true);
    }
}
