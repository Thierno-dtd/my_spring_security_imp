package com.example.security.logs.entities;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_user_email", columnList = "userEmail"),
        @Index(name = "idx_event_type", columnList = "eventType"),
        @Index(name = "idx_timestamp", columnList = "timestamp"),
        @Index(name = "idx_ip_address", columnList = "ipAddress")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 100)
    private String eventType;

    @Column(length = 255)
    private String userEmail;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(length = 45)
    private String ipAddress;

    @Column(length = 500)
    private String userAgent;

    @Column(length = 255)
    private String requestUri;

    @Column(length = 10)
    private String httpMethod;

    @Column(length = 50)
    private String sessionId;

    @Column(length = 20)
    private String threatLevel; // LOW, MEDIUM, HIGH, CRITICAL

    @Column
    private Long executionTime;

    @Column(columnDefinition = "JSON")
    private String additionalData; // Données JSON supplémentaires
}
