package com.example.security.repositories;

import com.example.security.entites.LoginAttempt;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.email = :email AND l.success = false AND l.attemptTime > :since")
    long countFailedAttemptsByEmailSince(@Param("email") String email, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.ipAddress = :ipAddress AND l.success = false AND l.attemptTime > :since")
    long countFailedAttemptsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    @Query("SELECT l FROM LoginAttempt l WHERE l.email = :email ORDER BY l.attemptTime DESC")
    List<LoginAttempt> findByEmailOrderByAttemptTimeDesc(@Param("email") String email);

    @Query("SELECT l FROM LoginAttempt l WHERE l.ipAddress = :ipAddress ORDER BY l.attemptTime DESC")
    List<LoginAttempt> findByIpAddressOrderByAttemptTimeDesc(@Param("ipAddress") String ipAddress);

    @Modifying
    @Query("DELETE FROM LoginAttempt l WHERE l.attemptTime < :cutoffDate")
    int cleanupOldLoginAttempts(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT l.ipAddress, COUNT(l) as attempts FROM LoginAttempt l WHERE l.success = false AND l.attemptTime > :since GROUP BY l.ipAddress HAVING COUNT(l) > :threshold")
    List<Object[]> findSuspiciousIpAddresses(@Param("since") LocalDateTime since, @Param("threshold") long threshold);

    @Query("SELECT la FROM LoginAttempt la WHERE la.email = :email ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findTop10ByEmailOrderByAttemptTimeDesc(@Param("email") String email, Pageable pageable);

    default List<LoginAttempt> findTop10ByEmailOrderByAttemptTimeDesc(String email) {
        return findTop10ByEmailOrderByAttemptTimeDesc(email, PageRequest.of(0, 10));
    }

    @Query("SELECT la.ipAddress, COUNT(la) FROM LoginAttempt la WHERE la.attemptTime >= :since AND la.success = false GROUP BY la.ipAddress HAVING COUNT(la) >= :threshold")
    List<Object[]> findSuspiciousIpAddresses(@Param("since") LocalDateTime since, @Param("threshold") int threshold);
}
