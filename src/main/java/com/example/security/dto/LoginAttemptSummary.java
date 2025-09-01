package com.example.security.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class LoginAttemptSummary {
    private String ipAddress;
    private Boolean success;
    private String failureReason;
    private LocalDateTime attemptTime;
    private String userAgent;
}