package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BulkRoleAssignmentRequest {
    @NotEmpty(message = "La liste des utilisateurs ne peut pas être vide")
    private List<Long> userIds;

    @NotNull(message = "L'ID du rôle est obligatoire")
    private Long roleId;

    private LocalDateTime expiresAt;
    private String assignmentReason;
    private Boolean sendNotifications = true;
}