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
public class LockoutInfo {
    private boolean locked;
    private int failedAttempts;
    private int remainingAttempts;
    private LocalDateTime lockedUntil;
    private int minutesRemaining;
}