package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionDto {
    private Long id;

    @NotBlank(message = "Le nom de la permission est obligatoire")
    private String name;

    @NotBlank(message = "La ressource est obligatoire")
    private String resource;

    @NotBlank(message = "L'action est obligatoire")
    private String action;

    private String description;
    private Boolean isActive;
    private Boolean isSystem;
    private String createdBy;
    private LocalDateTime createdAt;
    private String fullName;
}