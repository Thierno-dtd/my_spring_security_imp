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
public class UserRoleHistoryDto {
    private Long userId;
    private String userEmail;
    private Long roleId;
    private String roleName;
    private String action; // ASSIGNED, REVOKED, EXPIRED
    private String performedBy;
    private String reason;
    private LocalDateTime performedAt;
    private LocalDateTime expiresAt;
    private Boolean wasTemporary;
}