package com.example.security.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class CleanupResult {
    private int deletedCount;
    private LocalDateTime cutoffDate;
    private List<String> emails;
}