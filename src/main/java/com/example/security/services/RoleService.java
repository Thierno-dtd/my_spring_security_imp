package com.example.security.services;

import com.example.security.dto.*;
import com.example.security.entites.*;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.repositories.*;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RoleExclusionRepository roleExclusionRepository;
    private final RoleDependencyRepository roleDependencyRepository;
    private final UserRoleRepository userRoleRepository;
    private final AuditMicroserviceClient auditClient;
    private final NotificationClient notificationClient;
    private final AuthenticationService authenticationService;

    /**
     * Créer un nouveau rôle
     */
    @Transactional
    public RoleDto createRole(CreateRoleRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        User currentUser = authenticationService.getCurrentUser();

        try {
            // Vérifier si le rôle existe déjà
            if (roleRepository.existsByName(request.getName())) {
                throw new IllegalArgumentException("Un rôle avec ce nom existe déjà: " + request.getName());
            }

            // AUDIT: Début création rôle
            auditClient.logAuditEvent(
                    "ROLE_CREATION_STARTED",
                    currentUser.getEmail(),
                    String.format("Début création rôle: %s, catégorie: %s", request.getName(), request.getCategory()),
                    httpRequest,
                    0L
            );

            // Créer le rôle
            Role role = Role.builder()
                    .name(request.getName())
                    .description(request.getDescription())
                    .category(request.getCategory())
                    .priority(request.getPriority())
                    .isActive(true)
                    .isSystem(false)
                    .createdBy(currentUser.getEmail())
                    .build();

            role = roleRepository.save(role);

            // Assigner les permissions
            if (request.getPermissionIds() != null && !request.getPermissionIds().isEmpty()) {
                Set<Permission> permissions = new HashSet<>();
                for (Long permissionId : request.getPermissionIds()) {
                    Permission permission = permissionRepository.findById(permissionId)
                            .orElseThrow(() -> new EntityNotFoundException("Permission non trouvée: " + permissionId));
                    permissions.add(permission);
                }
                role.setPermissions(permissions);
                role = roleRepository.save(role);
            }

            // Créer les exclusions
            if (request.getExcludedRoleIds() != null && !request.getExcludedRoleIds().isEmpty()) {
                createRoleExclusions(role, request.getExcludedRoleIds(), currentUser.getEmail());
            }

            // Créer les dépendances
            if (request.getRequiredRoleIds() != null && !request.getRequiredRoleIds().isEmpty()) {
                createRoleDependencies(role, request.getRequiredRoleIds(), currentUser.getEmail());
            }

            long executionTime = System.currentTimeMillis() - startTime;

            // AUDIT: Rôle créé avec succès
            auditClient.logAuditEvent(
                    "ROLE_CREATED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Rôle créé: %s (ID: %d), permissions: %d, exclusions: %d, dépendances: %d",
                            role.getName(), role.getId(),
                            role.getPermissions().size(),
                            request.getExcludedRoleIds() != null ? request.getExcludedRoleIds().size() : 0,
                            request.getRequiredRoleIds() != null ? request.getRequiredRoleIds().size() : 0),
                    httpRequest,
                    executionTime
            );

            log.info("✅ Rôle créé: {} par {}", role.getName(), currentUser.getEmail());

            return mapToRoleDto(role);

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditClient.logSecurityEvent(
                    "ROLE_CREATION_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Échec création rôle: %s - %s", request.getName(), e.getMessage()),
                    httpRequest
            );
            log.error("❌ Erreur création rôle: {}", request.getName(), e);
            throw e;
        }
    }

    /**
     * Mettre à jour un rôle
     */
    @Transactional
    public RoleDto updateRole(Long roleId, UpdateRoleRequest request) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        User currentUser = authenticationService.getCurrentUser();

        try {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + roleId));

            if (role.getIsSystem()) {
                throw new IllegalArgumentException("Les rôles système ne peuvent pas être modifiés");
            }

            // Sauvegarder l'état ancien pour audit
            String oldValues = String.format("name=%s, description=%s, category=%s, isActive=%s, priority=%d",
                    role.getName(), role.getDescription(), role.getCategory(), role.getIsActive(), role.getPriority());

            // Mettre à jour les champs
            role.setName(request.getName());
            role.setDescription(request.getDescription());
            role.setCategory(request.getCategory());
            role.setIsActive(request.getIsActive());
            role.setPriority(request.getPriority());
            role.setUpdatedBy(currentUser.getEmail());

            // Mettre à jour les permissions
            if (request.getPermissionIds() != null) {
                updateRolePermissions(role, request.getPermissionIds());
            }

            role = roleRepository.save(role);

            String newValues = String.format("name=%s, description=%s, category=%s, isActive=%s, priority=%d",
                    role.getName(), role.getDescription(), role.getCategory(), role.getIsActive(), role.getPriority());

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_UPDATED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Rôle mis à jour: %s (ID: %d). Ancien: [%s] Nouveau: [%s]. Raison: %s",
                            role.getName(), role.getId(), oldValues, newValues, request.getReason()),
                    httpRequest,
                    0L
            );

            log.info("✅ Rôle mis à jour: {} par {}", role.getName(), currentUser.getEmail());

            return mapToRoleDto(role);

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_UPDATE_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Échec mise à jour rôle ID: %d - %s", roleId, e.getMessage()),
                    httpRequest
            );
            log.error("❌ Erreur mise à jour rôle ID: {}", roleId, e);
            throw e;
        }
    }

    /**
     * Supprimer un rôle
     */
    @Transactional
    public void deleteRole(Long roleId, String reason) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        User currentUser = authenticationService.getCurrentUser();

        try {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + roleId));

            if (role.getIsSystem()) {
                throw new IllegalArgumentException("Les rôles système ne peuvent pas être supprimés");
            }

            // Vérifier s'il y a des utilisateurs avec ce rôle
            Long activeUsersCount = userRoleRepository.countEffectiveUsersByRole(roleId, LocalDateTime.now());
            if (activeUsersCount > 0) {
                throw new IllegalArgumentException(
                        String.format("Impossible de supprimer le rôle. %d utilisateur(s) l'utilisent encore", activeUsersCount));
            }

            String roleName = role.getName();
            roleRepository.delete(role);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_DELETED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Rôle supprimé: %s (ID: %d). Raison: %s", roleName, roleId, reason),
                    httpRequest,
                    0L
            );

            log.info("✅ Rôle supprimé: {} par {}", roleName, currentUser.getEmail());

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_DELETE_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Échec suppression rôle ID: %d - %s", roleId, e.getMessage()),
                    httpRequest
            );
            log.error("❌ Erreur suppression rôle ID: {}", roleId, e);
            throw e;
        }
    }

    /**
     * Obtenir tous les rôles avec pagination
     */
    public PagedResponse<RoleDto> getAllRoles(int page, int size, String sortBy, String sortDir, String search) {
        Pageable pageable = PageRequest.of(page, size,
                sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending());

        Page<Role> rolesPage;
        if (search != null && !search.trim().isEmpty()) {
            rolesPage = roleRepository.findByNameContainingIgnoreCase(search, pageable);
        } else {
            rolesPage = roleRepository.findAll(pageable);
        }

        List<RoleDto> roleDtos = rolesPage.getContent().stream()
                .map(this::mapToRoleDto)
                .collect(Collectors.toList());

        return PagedResponse.<RoleDto>builder()
                .content(roleDtos)
                .page(page)
                .size(size)
                .totalElements(rolesPage.getTotalElements())
                .totalPages(rolesPage.getTotalPages())
                .first(rolesPage.isFirst())
                .last(rolesPage.isLast())
                .hasNext(rolesPage.hasNext())
                .hasPrevious(rolesPage.hasPrevious())
                .build();
    }

    /**
     * Obtenir un rôle par ID
     */
    public RoleDto getRoleById(Long roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + roleId));
        return mapToRoleDto(role);
    }

    /**
     * Obtenir les rôles par catégorie
     */
    public List<RoleDto> getRolesByCategory(String category) {
        return roleRepository.findByCategoryAndIsActiveTrue(category).stream()
                .map(this::mapToRoleDto)
                .collect(Collectors.toList());
    }

    /**
     * Valider l'affectation de rôles à un utilisateur
     */
    public RoleValidationResultDto validateUserRoles(Long userId, List<Long> roleIds) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<RoleConflictDto> conflicts = new ArrayList<>();

        try {
            List<Role> roles = roleRepository.findAllById(roleIds);

            // Vérifier les exclusions
            for (int i = 0; i < roles.size(); i++) {
                for (int j = i + 1; j < roles.size(); j++) {
                    Role role1 = roles.get(i);
                    Role role2 = roles.get(j);

                    if (roleExclusionRepository.areRolesExclusive(role1, role2)) {
                        conflicts.add(RoleConflictDto.builder()
                                .userId(userId)
                                .conflictType("EXCLUSION")
                                .description(String.format("Les rôles %s et %s sont mutuellement exclusifs",
                                        role1.getName(), role2.getName()))
                                .conflictingRoles(List.of(mapToRoleDto(role1), mapToRoleDto(role2)))
                                .severity("HIGH")
                                .recommendation("Choisir un seul des deux rôles")
                                .build());
                    }
                }
            }

            // Vérifier les dépendances
            for (Role role : roles) {
                List<Role> requiredRoles = roleDependencyRepository.findRequiredRolesByRole(role);
                for (Role requiredRole : requiredRoles) {
                    if (!roles.contains(requiredRole)) {
                        conflicts.add(RoleConflictDto.builder()
                                .userId(userId)
                                .conflictType("MISSING_DEPENDENCY")
                                .description(String.format("Le rôle %s nécessite le rôle %s",
                                        role.getName(), requiredRole.getName()))
                                .conflictingRoles(List.of(mapToRoleDto(role)))
                                .requiredRoles(List.of(mapToRoleDto(requiredRole)))
                                .severity("HIGH")
                                .recommendation("Ajouter le rôle requis ou supprimer le rôle dépendant")
                                .build());
                    }
                }
            }

            // Vérifier les rôles inactifs
            for (Role role : roles) {
                if (!role.getIsActive()) {
                    warnings.add(String.format("Le rôle %s est inactif", role.getName()));
                }
            }

        } catch (Exception e) {
            errors.add("Erreur lors de la validation: " + e.getMessage());
        }

        return RoleValidationResultDto.builder()
                .isValid(conflicts.isEmpty() && errors.isEmpty())
                .errors(errors)
                .warnings(warnings)
                .conflicts(conflicts)
                .summary(conflicts.isEmpty() && errors.isEmpty()
                        ? "Validation réussie"
                        : String.format("%d conflit(s) détecté(s)", conflicts.size()))
                .build();
    }

    /**
     * Créer les exclusions de rôles
     */
    private void createRoleExclusions(Role role, List<Long> excludedRoleIds, String createdBy) {
        for (Long excludedRoleId : excludedRoleIds) {
            Role excludedRole = roleRepository.findById(excludedRoleId)
                    .orElseThrow(() -> new EntityNotFoundException("Rôle exclu non trouvé: " + excludedRoleId));

            RoleExclusion exclusion = RoleExclusion.builder()
                    .role(role)
                    .excludedRole(excludedRole)
                    .reason("Exclusion mutuelle configurée")
                    .createdBy(createdBy)
                    .build();

            roleExclusionRepository.save(exclusion);

            // Créer l'exclusion inverse
            RoleExclusion inverseExclusion = RoleExclusion.builder()
                    .role(excludedRole)
                    .excludedRole(role)
                    .reason("Exclusion mutuelle inverse")
                    .createdBy(createdBy)
                    .build();

            roleExclusionRepository.save(inverseExclusion);
        }
    }

    /**
     * Créer les dépendances de rôles
     */
    private void createRoleDependencies(Role role, List<Long> requiredRoleIds, String createdBy) {
        for (Long requiredRoleId : requiredRoleIds) {
            Role requiredRole = roleRepository.findById(requiredRoleId)
                    .orElseThrow(() -> new EntityNotFoundException("Rôle requis non trouvé: " + requiredRoleId));

            RoleDependency dependency = RoleDependency.builder()
                    .role(role)
                    .requiredRole(requiredRole)
                    .dependencyType("PREREQUISITE")
                    .description("Dépendance requise pour ce rôle")
                    .createdBy(createdBy)
                    .build();

            roleDependencyRepository.save(dependency);
        }
    }

    /**
     * Mettre à jour les permissions d'un rôle
     */
    private void updateRolePermissions(Role role, List<Long> permissionIds) {
        Set<Permission> permissions = new HashSet<>();
        for (Long permissionId : permissionIds) {
            Permission permission = permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new EntityNotFoundException("Permission non trouvée: " + permissionId));
            permissions.add(permission);
        }
        role.setPermissions(permissions);
    }

    /**
     * Mapper Role vers RoleDto
     */
    private RoleDto mapToRoleDto(Role role) {
        List<PermissionDto> permissions = role.getPermissions().stream()
                .map(this::mapToPermissionDto)
                .collect(Collectors.toList());

        List<RoleDto> excludedRoles = roleExclusionRepository.findExcludedRolesByRole(role).stream()
                .map(this::mapToBasicRoleDto)
                .collect(Collectors.toList());

        List<RoleDto> requiredRoles = roleDependencyRepository.findRequiredRolesByRole(role).stream()
                .map(this::mapToBasicRoleDto)
                .collect(Collectors.toList());

        Long activeUsersCount = userRoleRepository.countEffectiveUsersByRole(role.getId(), LocalDateTime.now());

        return RoleDto.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .category(role.getCategory())
                .isActive(role.getIsActive())
                .isSystem(role.getIsSystem())
                .priority(role.getPriority())
                .createdBy(role.getCreatedBy())
                .updatedBy(role.getUpdatedBy())
                .createdAt(role.getCreatedAt())
                .updatedAt(role.getUpdatedAt())
                .permissions(permissions)
                .excludedRoles(excludedRoles)
                .requiredRoles(requiredRoles)
                .activeUsersCount(activeUsersCount)
                .build();
    }

    private RoleDto mapToBasicRoleDto(Role role) {
        return RoleDto.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .category(role.getCategory())
                .isActive(role.getIsActive())
                .isSystem(role.getIsSystem())
                .priority(role.getPriority())
                .build();
    }

    private PermissionDto mapToPermissionDto(Permission permission) {
        return PermissionDto.builder()
                .id(permission.getId())
                .name(permission.getName())
                .resource(permission.getResource())
                .action(permission.getAction())
                .description(permission.getDescription())
                .isActive(permission.getIsActive())
                .isSystem(permission.getIsSystem())
                .createdBy(permission.getCreatedBy())
                .createdAt(permission.getCreatedAt())
                .fullName(permission.getFullName())
                .build();
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
}