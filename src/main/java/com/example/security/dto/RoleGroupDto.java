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
public class RoleGroupDto {
    private Long id;

    @NotBlank(message = "Le nom du groupe est obligatoire")
    private String name;

    private String description;

    @NotNull(message = "Le statut actif est obligatoire")
    private Boolean isActive;

    private Boolean isDefault;
    private String createdBy;
    private String updatedBy;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    private List<RoleDto> roles;
    private Long activeUsersCount;
}