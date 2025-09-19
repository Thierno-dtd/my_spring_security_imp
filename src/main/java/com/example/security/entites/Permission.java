package com.example.security.entites;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "permissions", indexes = {
        @Index(name = "idx_permission_name", columnList = "name"),
        @Index(name = "idx_permission_resource", columnList = "resource"),
        @Index(name = "idx_permission_action", columnList = "action")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name; // ex: USER_READ, USER_WRITE, ADMIN_DELETE

    @Column(nullable = false)
    private String resource; // ex: USER, ROLE, SYSTEM

    @Column(nullable = false)
    private String action; // ex: READ, WRITE, DELETE, CREATE

    @Column(length = 500)
    private String description;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isSystem = false;

    @ManyToMany(mappedBy = "permissions")
    private Set<Role> roles = new HashSet<>();

    @Column(name = "created_by")
    private String createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (isActive == null) isActive = true;
        if (isSystem == null) isSystem = false;
    }

    public String getFullName() {
        return resource + "_" + action;
    }
}
