package com.example.security.dto;

import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserSummaryDto {
    private int id;
    private String email;
    private String name;
    private String pname;
    private TypeRoles role;
    private AccountStatus accountStatus;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;
    private Integer failedLoginAttempts;
    private Boolean isTemporarilyLocked;
}