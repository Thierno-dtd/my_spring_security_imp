package com.example.security.logs.repositories;

import com.example.security.logs.entities.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.LocalDateTime;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findByUserEmailContainingIgnoreCase(String userEmail, Pageable pageable);

    Page<AuditLog> findByEventType(String eventType, Pageable pageable);

    Page<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.userEmail = :email AND a.eventType = 'USER_LOGIN_FAILED' AND a.timestamp > :since")
    Long countFailedLoginsByUserSince(@Param("email") String email, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.ipAddress = :ip AND a.eventType = 'USER_LOGIN_FAILED' AND a.timestamp > :since")
    Long countFailedLoginsByIPSince(@Param("ip") String ip, @Param("since") LocalDateTime since);

    @Query("SELECT a.ipAddress, COUNT(a) as count FROM AuditLog a WHERE a.eventType = 'USER_LOGIN_FAILED' AND a.timestamp > :since GROUP BY a.ipAddress ORDER BY count DESC")
    List<Object[]> getTopFailedLoginIPs(@Param("since") LocalDateTime since);
}

