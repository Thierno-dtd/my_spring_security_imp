package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateRoleGroupRequest {
    @NotBlank(message = "Le nom du groupe est obligatoire")
    private String name;

    private String description;

    private Boolean isDefault = false;

    @NotEmpty(message = "Au moins un rôle est requis")
    private List<Long> roleIds;

    private String reason; // Raison de création pour audit
}