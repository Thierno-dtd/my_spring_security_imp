package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleAnalyticsDto {
    private Long totalRoles;
    private Long activeRoles;
    private Long systemRoles;
    private Long customRoles;
    private Long totalPermissions;
    private Long activePermissions;
    private Long totalRoleGroups;
    private Long activeRoleGroups;
    private Long totalUserRoleAssignments;
    private Long expiredRoleAssignments;
    private Map<String, Long> rolesByCategory;
    private Map<String, Long> permissionsByResource;
    private Map<String, Long> mostAssignedRoles;
    private LocalDateTime lastCalculated;
}