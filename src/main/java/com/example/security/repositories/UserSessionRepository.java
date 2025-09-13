package com.example.security.repositories;

import com.example.security.entites.User;
import com.example.security.entites.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findBySessionId(String sessionId);

    List<UserSession> findByUserAndIsActiveTrue(User user);

    List<UserSession> findByUserIdAndIsActiveTrue(int userId);

    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.isActive = true ORDER BY s.lastActivity DESC")
    List<UserSession> findActiveSessionsByUser(@Param("user") User user);

    @Query("SELECT s FROM UserSession s WHERE s.expiresAt < :now AND s.isActive = true")
    List<UserSession> findExpiredSessions(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE UserSession s SET s.isActive = false, s.logoutReason = 'EXPIRED' WHERE s.expiresAt < :now AND s.isActive = true")
    int deactivateExpiredSessions(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE UserSession s SET s.isActive = false, s.logoutReason = :reason WHERE s.user = :user AND s.sessionId != :currentSessionId AND s.isActive = true")
    int logoutOtherSessions(@Param("user") User user, @Param("currentSessionId") String currentSessionId, @Param("reason") String reason);

    @Modifying
    @Query("UPDATE UserSession s SET s.isActive = false, s.logoutReason = :reason WHERE s.sessionId = :sessionId")
    int logoutSession(@Param("sessionId") String sessionId, @Param("reason") String reason);

    @Query("SELECT COUNT(s) FROM UserSession s WHERE s.user = :user AND s.isActive = true")
    long countActiveSessionsByUser(@Param("user") User user);

    @Query("SELECT s FROM UserSession s WHERE s.lastActivity < :cutoffDate")
    List<UserSession> findInactiveSessions(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Modifying
    @Query("DELETE FROM UserSession s WHERE s.lastActivity < :cutoffDate AND s.isActive = false")
    int cleanupOldSessions(@Param("cutoffDate") LocalDateTime cutoffDate);
}
