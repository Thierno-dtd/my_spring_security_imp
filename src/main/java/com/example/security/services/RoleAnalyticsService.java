package com.example.security.services;

import com.example.security.dto.*;
import com.example.security.entites.*;
import com.example.security.repositories.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleAnalyticsService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RoleGroupRepository roleGroupRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleExclusionRepository roleExclusionRepository;
    private final RoleDependencyRepository roleDependencyRepository;

    /**
     * Obtenir les analytics générales des rôles
     */
    public RoleAnalyticsDto getRoleAnalytics() {
        try {
            // Statistiques de base
            Long totalRoles = roleRepository.count();
            Long activeRoles = (long) roleRepository.findByIsActiveTrue().size();
            Long systemRoles = (long) roleRepository.findSystemRoles().size();
            Long customRoles = totalRoles - systemRoles;

            Long totalPermissions = permissionRepository.count();
            Long activePermissions = (long) permissionRepository.findByIsActiveTrue().size();

            Long totalRoleGroups = roleGroupRepository.count();
            Long activeRoleGroups = (long) roleGroupRepository.findByIsActiveTrue().size();

            Long totalUserRoleAssignments = userRoleRepository.count();
            Long expiredRoleAssignments = (long) userRoleRepository.findExpiredUserRoles(LocalDateTime.now()).size();

            // Statistiques par catégorie
            Map<String, Long> rolesByCategory = calculateRolesByCategory();
            Map<String, Long> permissionsByResource = calculatePermissionsByResource();
            Map<String, Long> mostAssignedRoles = calculateMostAssignedRoles();

            return RoleAnalyticsDto.builder()
                    .totalRoles(totalRoles)
                    .activeRoles(activeRoles)
                    .systemRoles(systemRoles)
                    .customRoles(customRoles)
                    .totalPermissions(totalPermissions)
                    .activePermissions(activePermissions)
                    .totalRoleGroups(totalRoleGroups)
                    .activeRoleGroups(activeRoleGroups)
                    .totalUserRoleAssignments(totalUserRoleAssignments)
                    .expiredRoleAssignments(expiredRoleAssignments)
                    .rolesByCategory(rolesByCategory)
                    .permissionsByResource(permissionsByResource)
                    .mostAssignedRoles(mostAssignedRoles)
                    .lastCalculated(LocalDateTime.now())
                    .build();

        } catch (Exception e) {
            log.error("Erreur lors du calcul des analytics de rôles", e);
            throw e;
        }
    }

    /**
     * Détecter les conflits de rôles pour tous les utilisateurs
     */
    public List<RoleConflictDto> detectRoleConflicts() {
        List<RoleConflictDto> conflicts = new ArrayList<>();

        try {
            // Obtenir tous les utilisateurs avec des rôles actifs
            List<UserRole> activeUserRoles = userRoleRepository.findEffectiveUserRoles(null, LocalDateTime.now());

            // Grouper par utilisateur
            Map<Long, List<UserRole>> userRolesMap = activeUserRoles.stream()
                    .collect(Collectors.groupingBy(ur -> ur.getUser().getId()));

            for (Map.Entry<Long, List<UserRole>> entry : userRolesMap.entrySet()) {
                Long userId = entry.getKey();
                List<UserRole> userRoles = entry.getValue();
                User user = userRoles.get(0).getUser();

                // Vérifier les exclusions
                for (int i = 0; i < userRoles.size(); i++) {
                    for (int j = i + 1; j < userRoles.size(); j++) {
                        Role role1 = userRoles.get(i).getRole();
                        Role role2 = userRoles.get(j).getRole();

                        if (roleExclusionRepository.areRolesExclusive(role1, role2)) {
                            conflicts.add(RoleConflictDto.builder()
                                    .userId(userId)
                                    .userEmail(user.getEmail())
                                    .conflictType("EXCLUSION")
                                    .description(String.format("L'utilisateur %s possède les rôles mutuellement exclusifs %s et %s",
                                            user.getEmail(), role1.getName(), role2.getName()))
                                    .conflictingRoles(List.of(mapToBasicRoleDto(role1), mapToBasicRoleDto(role2)))
                                    .severity("HIGH")
                                    .recommendation("Supprimer un des deux rôles conflictuels")
                                    .build());
                        }
                    }
                }

                // Vérifier les dépendances manquantes
                List<Role> userRolesList = userRoles.stream().map(UserRole::getRole).collect(Collectors.toList());
                for (Role role : userRolesList) {
                    List<Role> requiredRoles = roleDependencyRepository.findRequiredRolesByRole(role);
                    for (Role requiredRole : requiredRoles) {
                        if (!userRolesList.contains(requiredRole)) {
                            conflicts.add(RoleConflictDto.builder()
                                    .userId(userId)
                                    .userEmail(user.getEmail())
                                    .conflictType("MISSING_DEPENDENCY")
                                    .description(String.format("L'utilisateur %s possède le rôle %s qui nécessite le rôle %s",
                                            user.getEmail(), role.getName(), requiredRole.getName()))
                                    .conflictingRoles(List.of(mapToBasicRoleDto(role)))
                                    .requiredRoles(List.of(mapToBasicRoleDto(requiredRole)))
                                    .severity("MEDIUM")
                                    .recommendation("Ajouter le rôle requis ou supprimer le rôle dépendant")
                                    .build());
                        }
                    }
                }
            }

        } catch (Exception e) {
            log.error("Erreur lors de la détection des conflits de rôles", e);
            throw e;
        }

        return conflicts;
    }

    /**
     * Générer la matrice permissions-rôles
     */
    public RolePermissionMatrixDto generatePermissionMatrix() {
        try {
            List<Role> roles = roleRepository.findByIsActiveTrue();
            List<Permission> permissions = permissionRepository.findByIsActiveTrue();

            List<String> resources = permissionRepository.findAllActiveResources();
            List<String> actions = permissionRepository.findAllActiveActions();

            Map<String, Map<String, Boolean>> matrix = new HashMap<>();

            for (Role role : roles) {
                Map<String, Boolean> rolePermissions = new HashMap<>();
                Set<Permission> rolePermissionSet = role.getPermissions();

                for (Permission permission : permissions) {
                    rolePermissions.put(permission.getName(), rolePermissionSet.contains(permission));
                }

                matrix.put(role.getName(), rolePermissions);
            }

            return RolePermissionMatrixDto.builder()
                    .roles(roles.stream().map(this::mapToBasicRoleDto).collect(Collectors.toList()))
                    .permissions(permissions.stream().map(this::mapToBasicPermissionDto).collect(Collectors.toList()))
                    .matrix(matrix)
                    .resources(resources)
                    .actions(actions)
                    .build();

        } catch (Exception e) {
            log.error("Erreur lors de la génération de la matrice de permissions", e);
            throw e;
        }
    }

    private Map<String, Long> calculateRolesByCategory() {
        List<Role> allRoles = roleRepository.findAll();
        return allRoles.stream()
                .collect(Collectors.groupingBy(
                        Role::getCategory,
                        Collectors.counting()
                ));
    }

    private Map<String, Long> calculatePermissionsByResource() {
        List<Permission> allPermissions = permissionRepository.findAll();
        return allPermissions.stream()
                .collect(Collectors.groupingBy(
                        Permission::getResource,
                        Collectors.counting()
                ));
    }

    private Map<String, Long> calculateMostAssignedRoles() {
        List<UserRole> activeAssignments = userRoleRepository.findEffectiveUserRoles(null, LocalDateTime.now());

        Map<String, Long> roleCounts = activeAssignments.stream()
                .collect(Collectors.groupingBy(
                        ur -> ur.getRole().getName(),
                        Collectors.counting()
                ));

        // Retourner les 10 rôles les plus assignés
        return roleCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (e1, e2) -> e1,
                        java.util.LinkedHashMap::new
                ));
    }

    private RoleDto mapToBasicRoleDto(Role role) {
        return RoleDto.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .category(role.getCategory())
                .isActive(role.getIsActive())
                .priority(role.getPriority())
                .build();
    }

    private PermissionDto mapToBasicPermissionDto(Permission permission) {
        return PermissionDto.builder()
                .id(permission.getId())
                .name(permission.getName())
                .resource(permission.getResource())
                .action(permission.getAction())
                .description(permission.getDescription())
                .isActive(permission.getIsActive())
                .fullName(permission.getFullName())
                .build();
    }
}
