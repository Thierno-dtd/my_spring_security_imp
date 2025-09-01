package com.example.security.repositories;

import com.example.security.constants.AccountStatus;
import com.example.security.entites.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);

    Optional<User> findByEmailVerificationToken(String token);

    @Query("SELECT u FROM User u WHERE u.emailVerificationExpiresAt < :now AND u.emailVerified = false")
    List<User> findExpiredUnverifiedUsers(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM User u WHERE u.emailVerificationExpiresAt < :cutoffDate AND u.emailVerified = false")
    int deleteExpiredUnverifiedUsers(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT COUNT(u) FROM User u WHERE u.accountStatus = :status")
    long countByAccountStatus(@Param("status") AccountStatus status);

    // Méthode pour nettoyer les comptes non vérifiés après X jours
    @Modifying
    @Query("DELETE FROM User u WHERE u.createdAt < :cutoffDate AND u.emailVerified = false")

    int cleanupUnverifiedAccountsOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);

    // NOUVELLES méthodes pour password reset
    Optional<User> findByPasswordResetToken(String token);

    @Query("SELECT u FROM User u WHERE u.passwordResetExpiresAt < :now AND u.passwordResetToken IS NOT NULL")
    List<User> findExpiredPasswordResetTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE User u SET u.passwordResetToken = NULL, u.passwordResetExpiresAt = NULL WHERE u.passwordResetExpiresAt < :cutoffDate")
    int cleanupExpiredPasswordResetTokens(@Param("cutoffDate") LocalDateTime cutoffDate);

    // NOUVELLES méthodes pour email change
    Optional<User> findByEmailChangeToken(String token);
    Optional<User> findByPendingEmail(String pendingEmail);

    @Modifying
    @Query("UPDATE User u SET u.emailChangeToken = NULL, u.emailChangeExpiresAt = NULL, u.pendingEmail = NULL WHERE u.emailChangeExpiresAt < :cutoffDate")
    int cleanupExpiredEmailChangeTokens(@Param("cutoffDate") LocalDateTime cutoffDate);

    // NOUVELLES méthodes pour account lockout
    @Query("SELECT u FROM User u WHERE u.lockedUntil < :now AND u.lockedUntil IS NOT NULL")
    List<User> findUsersToUnlock(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = NULL WHERE u.lockedUntil < :now")
    int unlockExpiredLockouts(@Param("now") LocalDateTime now);

    @Query("SELECT COUNT(u) FROM User u WHERE u.failedLoginAttempts >= :threshold")
    long countUsersWithFailedAttempts(@Param("threshold") int threshold);

    // NOUVELLES méthodes pour OAuth2
    Optional<User> findByGoogleId(String googleId);

    @Query("SELECT u FROM User u WHERE u.registrationMethod = :method")
    List<User> findByRegistrationMethod(@Param("method") String method);

    // Méthodes de sécurité et monitoring
    @Query("SELECT u FROM User u WHERE u.lastLoginAttempt BETWEEN :start AND :end")
    List<User> findUsersWithLoginAttemptsBetween(@Param("start") LocalDateTime start, @Param("end") LocalDateTime end);

    @Query("SELECT COUNT(u) FROM User u WHERE u.lastSuccessfulLogin < :cutoffDate")
    long countInactiveUsers(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT u FROM User u WHERE u.email LIKE %:search% OR u.name LIKE %:search% ORDER BY u.createdAt DESC")
    Page<User> findByEmailContainingOrNameContainingIgnoreCase(@Param("search") String search,
                                                               @Param("search") String search2,
                                                               Pageable pageable);
}
