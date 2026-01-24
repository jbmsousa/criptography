package cv.sousa.server.repository;

import cv.sousa.server.model.User;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserRepository implements PanacheRepository<User> {

    public Optional<User> findByUserId(String nif) {
        return find("nif", nif).firstResultOptional();
    }

    public Optional<User> findByNif(String nif) {
        return find("nif", nif).firstResultOptional();
    }

    public Optional<User> findByEmail(String email) {
        return find("email", email).firstResultOptional();
    }

    public boolean existsByUserId(String nif) {
        return count("nif", nif) > 0;
    }

    public boolean existsByNif(String nif) {
        return count("nif", nif) > 0;
    }

    public boolean existsByEmail(String email) {
        return count("email", email) > 0;
    }

    public List<User> findOnlineUsers() {
        return list("isOnline", true);
    }

    public List<User> findAllExcept(String nif) {
        return list("nif != ?1", nif);
    }

    public void updateOnlineStatus(String nif, boolean isOnline) {
        update("isOnline = ?1 WHERE nif = ?2", isOnline, nif);
    }

    public void updateLastLogin(String nif) {
        update("lastLogin = ?1 WHERE nif = ?2", java.time.LocalDateTime.now(), nif);
    }

    public void setAllUsersOffline() {
        update("isOnline = false WHERE isOnline = true");
    }
}
