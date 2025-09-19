package com.example.security.entites;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_roles",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "role_id"}),
        indexes = {
                @Index(name = "idx_userrole_user", columnList = "user_id"),
                @Index(name = "idx_userrole_role", columnList = "role_id"),
                @Index(name = "idx_userrole_active", columnList = "is_active")
        })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRole {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt; // Rôle temporaire

    @Column(name = "assigned_by")
    private String assignedBy;

    @Column(name = "assignment_reason")
    private String assignmentReason;

    @CreationTimestamp
    @Column(name = "assigned_at", nullable = false)
    private LocalDateTime assignedAt;

    @PrePersist
    protected void onCreate() {
        assignedAt = LocalDateTime.now();
        if (isActive == null) isActive = true;
    }

    // Méthodes utilitaires
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(LocalDateTime.now());
    }

    public boolean isTemporary() {
        return expiresAt != null;
    }

    public boolean isEffective() {
        return isActive && !isExpired();
    }
}
