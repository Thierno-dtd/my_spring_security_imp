package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleAssignmentResultDto {
    private Integer successCount;
    private Integer failureCount;
    private List<String> successfulAssignments;
    private List<String> failedAssignments;
    private List<String> warnings;
    private String summary;
}