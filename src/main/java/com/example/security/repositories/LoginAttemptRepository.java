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

    /**
     * Compte les tentatives échouées par IP depuis une date donnée
     */
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.ipAddress = :ipAddress AND l.success = false AND l.attemptTime > :since")
    long countFailedAttemptsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    @Query("SELECT l FROM LoginAttempt l WHERE l.email = :email ORDER BY l.attemptTime DESC")
    List<LoginAttempt> findByEmailOrderByAttemptTimeDesc(@Param("email") String email);

    @Query("SELECT l FROM LoginAttempt l WHERE l.ipAddress = :ipAddress ORDER BY l.attemptTime DESC")
    List<LoginAttempt> findByIpAddressOrderByAttemptTimeDesc(@Param("ipAddress") String ipAddress);

    /**
     * Nettoie les anciennes tentatives de connexion
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt l WHERE l.attemptTime < :cutoffDate")
    int cleanupOldLoginAttempts(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT l.ipAddress, COUNT(l) as attempts FROM LoginAttempt l WHERE l.success = false AND l.attemptTime > :since GROUP BY l.ipAddress HAVING COUNT(l) > :threshold")
    List<Object[]> findSuspiciousIpAddresses(@Param("since") LocalDateTime since, @Param("threshold") long threshold);

    @Query("SELECT la FROM LoginAttempt la WHERE la.email = :email ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findTop10ByEmailOrderByAttemptTimeDesc(@Param("email") String email, Pageable pageable);

    /**
     * Trouve les dernières tentatives de connexion pour un email donné
     */
    default List<LoginAttempt> findTop10ByEmailOrderByAttemptTimeDesc(String email) {
        return findTop10ByEmailOrderByAttemptTimeDesc(email, PageRequest.of(0, 10));
    }

    /**
     * Trouve les IPs suspectes avec un nombre élevé de tentatives échouées
     */
    @Query("SELECT la.ipAddress, COUNT(la) FROM LoginAttempt la WHERE la.attemptTime >= :since AND la.success = false GROUP BY la.ipAddress HAVING COUNT(la) >= :threshold")
    List<Object[]> findSuspiciousIpAddresses(@Param("since") LocalDateTime since, @Param("threshold") int threshold);

    /**
     * Compte les tentatives échouées depuis une date donnée
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.success = false AND la.attemptTime >= :since")
    long countFailedAttemptsSince(@Param("since") LocalDateTime since);

    /**
     * Trouve les tentatives de connexion récentes par IP
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.ipAddress = :ipAddress " +
            "AND la.attemptTime >= :since ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findRecentAttemptsByIp(@Param("ipAddress") String ipAddress,
                                              @Param("since") LocalDateTime since);

    /**
     * Compte toutes les tentatives de connexion
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la")
    long count();

    /**
     * Statistiques des tentatives par heure pour une période donnée
     */
    @Query("SELECT FUNCTION('HOUR', la.attemptTime) as hour, COUNT(la) as attempts " +
            "FROM LoginAttempt la WHERE la.attemptTime BETWEEN :start AND :end " +
            "GROUP BY FUNCTION('HOUR', la.attemptTime) " +
            "ORDER BY FUNCTION('HOUR', la.attemptTime)")
    List<Object[]> getHourlyAttemptStats(@Param("start") LocalDateTime start,
                                         @Param("end") LocalDateTime end);

    /**
     * Top des IPs avec le plus de tentatives échouées
     */
    @Query("SELECT la.ipAddress, COUNT(la) as failures, MAX(la.attemptTime) as lastAttempt " +
            "FROM LoginAttempt la WHERE la.success = false AND la.attemptTime >= :since " +
            "GROUP BY la.ipAddress " +
            "ORDER BY COUNT(la) DESC")
    List<Object[]> getTopFailedIPs(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * Trouve les patterns d'attaque (même User-Agent, même IP, etc.)
     */
    @Query("SELECT la.userAgent, la.ipAddress, COUNT(la) as attempts " +
            "FROM LoginAttempt la WHERE la.success = false AND la.attemptTime >= :since " +
            "GROUP BY la.userAgent, la.ipAddress " +
            "HAVING COUNT(la) >= :minAttempts " +
            "ORDER BY COUNT(la) DESC")
    List<Object[]> findAttackPatterns(@Param("since") LocalDateTime since,
                                      @Param("minAttempts") int minAttempts);

    /**
     * Récupère les emails distincts qui se sont connectés depuis une IP donnée
     * à partir d'une date précise.
     */
    @Query("SELECT DISTINCT la.email " +
            "FROM LoginAttempt la " +
            "WHERE la.ipAddress = :ipAddress " +
            "AND la.attemptTime >= :since")
    List<String> findDistinctEmailsByIpAndSince(@Param("ipAddress") String ipAddress,
                                                @Param("since") LocalDateTime since);

}
