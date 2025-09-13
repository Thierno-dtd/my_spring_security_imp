package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityStats {
    private long currentlyLockedAccounts;
    private long totalLoginAttempts;
    private long suspiciousIpCount;
}