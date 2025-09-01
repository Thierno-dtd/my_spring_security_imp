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
public class SessionInfo {
    private String sessionId;
    private String deviceInfo;
    private String ipAddress;
    private String location;
    private LocalDateTime lastActivity;
    private boolean current;
    private String browserInfo;
}
