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
public class RoleConflictDto {
    private Long userId;
    private String userEmail;
    private String conflictType; // EXCLUSION, MISSING_DEPENDENCY
    private String description;
    private List<RoleDto> conflictingRoles;
    private List<RoleDto> requiredRoles;
    private String severity; // HIGH, MEDIUM, LOW
    private String recommendation;
}