package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssignRoleRequest {
    @NotNull(message = "L'ID utilisateur est obligatoire")
    private Long userId;

    @NotNull(message = "L'ID du rôle est obligatoire")
    private Long roleId;

    private LocalDateTime expiresAt; // Pour rôles temporaires
    private String assignmentReason;
    private Boolean sendNotification = true;
}