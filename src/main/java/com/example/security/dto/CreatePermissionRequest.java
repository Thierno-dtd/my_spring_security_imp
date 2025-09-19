package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreatePermissionRequest {
    @NotBlank(message = "Le nom de la permission est obligatoire")
    private String name;

    @NotBlank(message = "La ressource est obligatoire")
    private String resource;

    @NotBlank(message = "L'action est obligatoire")
    private String action;

    private String description;
    private String reason; // Raison de création pour audit
}