package com.example.security.entites;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles", indexes = {
        @Index(name = "idx_role_name", columnList = "name"),
        @Index(name = "idx_role_category", columnList = "category"),
        @Index(name = "idx_role_active", columnList = "is_active")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    @Column(length = 500)
    private String description;

    @Column(nullable = false)
    private String category; // SYSTEM, BUSINESS, FUNCTIONAL

    @Column(nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isSystem = false; // true pour les rôles système non modifiables

    @Column(nullable = false)
    private Integer priority = 0; // Priorité du rôle (plus élevé = plus important)

    @ManyToMany(mappedBy = "roles")
    private Set<RoleGroup> roleGroups = new HashSet<>();

    @ManyToMany
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions = new HashSet<>();

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<RoleExclusion> exclusions = new HashSet<>();

    @OneToMany(mappedBy = "requiredRole", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<RoleDependency> dependencies = new HashSet<>();

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "updated_by")
    private String updatedBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (isActive == null) isActive = true;
        if (isSystem == null) isSystem = false;
        if (priority == null) priority = 0;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Méthodes utilitaires
    public boolean canBeModified() {
        return !isSystem;
    }

    public boolean isHighPriority() {
        return priority >= 100;
    }
}
