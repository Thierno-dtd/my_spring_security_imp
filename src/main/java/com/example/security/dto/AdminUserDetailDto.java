package com.example.security.dto;

import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class AdminUserDetailDto {
    private Long id;
    private String email;
    private String name;
    private String pname;
    private TypeRoles role;
    private AccountStatus accountStatus;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;
    private LocalDateTime updatedAt;
    private Integer failedLoginAttempts;
    private Boolean isTemporarilyLocked;
    private LocalDateTime lockedUntil;
    private String lastLoginIp;
    private String createdByAdmin;
    private List<SessionInfo> activeSessions;
    private List<LoginAttemptSummary> recentLoginAttempts;
}