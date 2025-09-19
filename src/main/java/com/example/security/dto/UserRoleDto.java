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
public class UserRoleDto {
    private Long id;
    private Long userId;
    private String userEmail;
    private String userName;
    private Long roleId;
    private String roleName;
    private Boolean isActive;
    private Boolean isTemporary;
    private Boolean isExpired;
    private LocalDateTime expiresAt;
    private String assignedBy;
    private String assignmentReason;
    private LocalDateTime assignedAt;
}