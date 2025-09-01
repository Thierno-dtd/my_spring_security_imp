package com.example.security.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserProfileResponse {
    private int id;
    private String email;
    private String name;
    private String pname;
    private String role;
    private String accountStatus;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;
    private Integer failedLoginAttempts;
    private Boolean isTemporarilyLocked;
    private LocalDateTime lockedUntil;
}