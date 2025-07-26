package com.example.security.logs;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {

    Page<SecurityLog> findByThreatLevel(String threatLevel, Pageable pageable);

    Page<SecurityLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);

    @Query("SELECT COUNT(s) FROM SecurityLog s WHERE s.threatLevel IN ('HIGH', 'CRITICAL') AND s.timestamp > :since")
    Long countHighThreatsSince(@Param("since") LocalDateTime since);
}
