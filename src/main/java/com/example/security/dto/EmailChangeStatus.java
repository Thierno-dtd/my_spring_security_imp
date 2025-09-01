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
public class EmailChangeStatus {
    private boolean hasPendingChange;
    private String pendingEmail;
    private LocalDateTime expiresAt;
    private long hoursRemaining;
}