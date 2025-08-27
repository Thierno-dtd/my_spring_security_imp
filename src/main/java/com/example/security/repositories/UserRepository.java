package com.example.security.repositories;

import com.example.security.constants.AccountStatus;
import com.example.security.entites.User;
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
}
