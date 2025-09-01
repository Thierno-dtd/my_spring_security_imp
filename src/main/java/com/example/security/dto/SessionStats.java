package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionStats {
    private long totalActiveSessions;
    private long sessionsLast24h;
    private long sessionsLast7days;
    private long averageSessionDuration;
}