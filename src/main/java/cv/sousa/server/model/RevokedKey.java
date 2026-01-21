package cv.sousa.server.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "revoked_keys")
public class RevokedKey extends PanacheEntity {
  @Column(unique = true, nullable = false)
  public String publicKeyFingerprint;

  public String userId;
  public String reason;
  public LocalDateTime revokedAt = LocalDateTime.now();

  public static RevokedKey findByFingerprint(String fp) {
    return find("publicKeyFingerprint", fp).firstResult();
  }
}