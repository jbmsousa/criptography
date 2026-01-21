package cv.sousa.server.repository;

import cv.sousa.server.model.User;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserRepository implements PanacheRepository<User> {

    public Optional<User> findByUserId(String userId) {
        return find("userId", userId).firstResultOptional();
    }

    public boolean existsByUserId(String userId) {
        return count("userId", userId) > 0;
    }

    public List<User> findOnlineUsers() {
        return list("isOnline", true);
    }

    public List<User> findAllExcept(String userId) {
        return list("userId != ?1", userId);
    }

    public void updateOnlineStatus(String userId, boolean isOnline) {
        update("isOnline = ?1 WHERE userId = ?2", isOnline, userId);
    }

    public void updateLastLogin(String userId) {
        update("lastLogin = ?1 WHERE userId = ?2", java.time.LocalDateTime.now(), userId);
    }
}
