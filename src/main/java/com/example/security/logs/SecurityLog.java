package com.example.security.logs;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_logs", indexes = {
        @Index(name = "idx_threat_level", columnList = "threatLevel"),
        @Index(name = "idx_security_timestamp", columnList = "timestamp"),
        @Index(name = "idx_blocked", columnList = "blocked")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 100)
    private String securityEvent;

    @Column(length = 255)
    private String userEmail;

    @Column(nullable = false, length = 20)
    private String threatLevel;

    @Column(length = 45)
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column
    private Boolean blocked = false; // Si l'action a été bloquée

    @Column(length = 255)
    private String countermeasure; // Action prise (blocage IP, etc.)
}

