package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleAuditDto {
    private Long id;
    private String action; // CREATE, UPDATE, DELETE, ASSIGN, REVOKE
    private String entityType; // ROLE, PERMISSION, ROLE_GROUP
    private Long entityId;
    private String entityName;
    private String performedBy;
    private String targetUser; // Pour les assignments
    private String oldValues;
    private String newValues;
    private String reason;
    private LocalDateTime performedAt;
    private String ipAddress;
}