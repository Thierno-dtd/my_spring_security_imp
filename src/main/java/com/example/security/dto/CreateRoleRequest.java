package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateRoleRequest {
    @NotBlank(message = "Le nom du rôle est obligatoire")
    private String name;

    private String description;

    @NotBlank(message = "La catégorie est obligatoire")
    private String category;

    @NotNull(message = "La priorité est obligatoire")
    private Integer priority;

    @NotEmpty(message = "Au moins une permission est requise")
    private List<Long> permissionIds;

    private List<Long> excludedRoleIds;
    private List<Long> requiredRoleIds;
    private String reason; // Raison de création pour audit
}