package com.example.security.dto;

import com.example.security.constants.AccountStatus;
import lombok.Data;

import jakarta.validation.constraints.NotNull;

@Data
public class UserStatusUpdateRequest {
    @NotNull
    private AccountStatus newStatus;
    private String reason;
    private Boolean sendNotification = true;
}