package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleDto {
    private Long id;

    @NotBlank(message = "Le nom du rôle est obligatoire")
    private String name;

    private String description;

    @NotBlank(message = "La catégorie est obligatoire")
    private String category;

    @NotNull(message = "Le statut actif est obligatoire")
    private Boolean isActive;

    private Boolean isSystem;
    private Integer priority;
    private String createdBy;
    private String updatedBy;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Relations
    private List<PermissionDto> permissions;
    private List<RoleGroupDto> roleGroups;
    private List<RoleDto> excludedRoles;
    private List<RoleDto> requiredRoles;
    private Long activeUsersCount;
}