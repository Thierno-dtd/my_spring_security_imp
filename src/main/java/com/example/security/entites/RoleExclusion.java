package com.example.security.entites;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "role_exclusions",
        uniqueConstraints = @UniqueConstraint(columnNames = {"role_id", "excluded_role_id"}),
        indexes = {
                @Index(name = "idx_exclusion_role", columnList = "role_id"),
                @Index(name = "idx_exclusion_excluded", columnList = "excluded_role_id")
        })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleExclusion {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "excluded_role_id", nullable = false)
    private Role excludedRole;

    @Column(nullable = false)
    private String reason; // Raison de l'exclusion

    @Column(nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @Column(name = "created_by")
    private String createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (isActive == null) isActive = true;
    }
}
