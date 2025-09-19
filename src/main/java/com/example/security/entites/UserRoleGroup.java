package com.example.security.entites;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_role_groups",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "rolegroup_id"}),
        indexes = {
                @Index(name = "idx_userrolegroup_user", columnList = "user_id"),
                @Index(name = "idx_userrolegroup_group", columnList = "rolegroup_id"),
                @Index(name = "idx_userrolegroup_active", columnList = "is_active")
        })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRoleGroup {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rolegroup_id", nullable = false)
    private RoleGroup roleGroup;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "assigned_by")
    private String assignedBy;

    @CreationTimestamp
    @Column(name = "assigned_at", nullable = false)
    private LocalDateTime assignedAt;

    @PrePersist
    protected void onCreate() {
        assignedAt = LocalDateTime.now();
        if (isActive == null) isActive = true;
    }

    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(LocalDateTime.now());
    }

    public boolean isEffective() {
        return isActive && !isExpired();
    }
}
