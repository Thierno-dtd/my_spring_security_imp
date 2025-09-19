package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RolePermissionMatrixDto {
    private List<RoleDto> roles;
    private List<PermissionDto> permissions;
    private Map<String, Map<String, Boolean>> matrix; // role -> permission -> hasPermission
    private List<String> resources;
    private List<String> actions;
}