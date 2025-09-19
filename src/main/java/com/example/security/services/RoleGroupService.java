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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleGroupService {

    private final RoleGroupRepository roleGroupRepository;
    private final RoleRepository roleRepository;
    private final UserRoleGroupRepository userRoleGroupRepository;
    private final UserRepository userRepository;
    private final AuditMicroserviceClient auditClient;
    private final NotificationClient notificationClient;
    private final AuthenticationService authenticationService;

    /**
     * Créer un nouveau groupe de rôles
     */
    @Transactional
    public RoleGroupDto createRoleGroup(CreateRoleGroupRequest request) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            // Vérifier si le groupe existe déjà
            if (roleGroupRepository.existsByName(request.getName())) {
                throw new IllegalArgumentException("Un groupe avec ce nom existe déjà: " + request.getName());
            }

            // Créer le groupe
            RoleGroup roleGroup = RoleGroup.builder()
                    .name(request.getName())
                    .description(request.getDescription())
                    .isActive(true)
                    .isDefault(request.getIsDefault())
                    .createdBy(currentUser.getEmail())
                    .build();

            // Ajouter les rôles
            if (request.getRoleIds() != null && !request.getRoleIds().isEmpty()) {
                Set<Role> roles = new HashSet<>();
                for (Long roleId : request.getRoleIds()) {
                    Role role = roleRepository.findById(roleId)
                            .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + roleId));
                    roles.add(role);
                }
                roleGroup.setRoles(roles);
            }

            roleGroup = roleGroupRepository.save(roleGroup);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_GROUP_CREATED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Groupe de rôles créé: %s (ID: %d), rôles: %d. Raison: %s",
                            roleGroup.getName(), roleGroup.getId(), roleGroup.getRoles().size(), request.getReason()),
                    httpRequest,
                    0L
            );

            log.info("✅ Groupe de rôles créé: {} par {}", roleGroup.getName(), currentUser.getEmail());

            return mapToRoleGroupDto(roleGroup);

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_GROUP_CREATION_FAILED",
                    currentUser.getEmail(),
                    "MEDIUM",
                    String.format("Échec création groupe: %s - %s", request.getName(), e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Assigner un groupe de rôles à un utilisateur
     */
    @Transactional
    public void assignRoleGroupToUser(Long userId, Long roleGroupId, LocalDateTime expiresAt, String reason) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + userId));

            RoleGroup roleGroup = roleGroupRepository.findById(roleGroupId)
                    .orElseThrow(() -> new EntityNotFoundException("Groupe de rôles non trouvé: " + roleGroupId));

            // Vérifier si l'assignation existe déjà
            if (userRoleGroupRepository.existsByUserAndRoleGroup(user, roleGroup)) {
                throw new IllegalArgumentException(
                        String.format("L'utilisateur %s possède déjà le groupe %s", user.getEmail(), roleGroup.getName()));
            }

            // Créer l'assignation
            UserRoleGroup userRoleGroup = UserRoleGroup.builder()
                    .user(user)
                    .roleGroup(roleGroup)
                    .isActive(true)
                    .expiresAt(expiresAt)
                    .assignedBy(currentUser.getEmail())
                    .build();

            userRoleGroupRepository.save(userRoleGroup);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_GROUP_ASSIGNED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Groupe de rôles assigné: %s à %s (ID: %d). Expire: %s. Raison: %s",
                            roleGroup.getName(), user.getEmail(), user.getId(), expiresAt, reason),
                    httpRequest,
                    0L
            );

            log.info("✅ Groupe de rôles {} assigné à {} par {}",
                    roleGroup.getName(), user.getEmail(), currentUser.getEmail());

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_GROUP_ASSIGNMENT_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Échec assignation groupe ID %d à utilisateur ID %d: %s",
                            roleGroupId, userId, e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Obtenir tous les groupes de rôles
     */
    public PagedResponse<RoleGroupDto> getAllRoleGroups(int page, int size, String sortBy, String sortDir, String search) {
        Pageable pageable = PageRequest.of(page, size,
                sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending());

        Page<RoleGroup> roleGroupsPage;
        if (search != null && !search.trim().isEmpty()) {
            roleGroupsPage = roleGroupRepository.findByNameContainingIgnoreCase(search, pageable);
        } else {
            roleGroupsPage = roleGroupRepository.findAll(pageable);
        }

        List<RoleGroupDto> roleGroupDtos = roleGroupsPage.getContent().stream()
                .map(this::mapToRoleGroupDto)
                .collect(Collectors.toList());

        return PagedResponse.<RoleGroupDto>builder()
                .content(roleGroupDtos)
                .page(page)
                .size(size)
                .totalElements(roleGroupsPage.getTotalElements())
                .totalPages(roleGroupsPage.getTotalPages())
                .first(roleGroupsPage.isFirst())
                .last(roleGroupsPage.isLast())
                .hasNext(roleGroupsPage.hasNext())
                .hasPrevious(roleGroupsPage.hasPrevious())
                .build();
    }

    /**
     * Supprimer un groupe de rôles
     */
    @Transactional
    public void deleteRoleGroup(Long roleGroupId, String reason) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            RoleGroup roleGroup = roleGroupRepository.findById(roleGroupId)
                    .orElseThrow(() -> new EntityNotFoundException("Groupe de rôles non trouvé: " + roleGroupId));

            // Vérifier s'il y a des utilisateurs avec ce groupe
            Long activeUsersCount = roleGroupRepository.countActiveUsersByRoleGroup(roleGroupId);
            if (activeUsersCount > 0) {
                throw new IllegalArgumentException(
                        String.format("Impossible de supprimer le groupe. %d utilisateur(s) l'utilisent encore", activeUsersCount));
            }

            String groupName = roleGroup.getName();
            roleGroupRepository.delete(roleGroup);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_GROUP_DELETED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Groupe de rôles supprimé: %s (ID: %d). Raison: %s", groupName, roleGroupId, reason),
                    httpRequest,
                    0L
            );

            log.info("✅ Groupe de rôles supprimé: {} par {}", groupName, currentUser.getEmail());

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_GROUP_DELETE_FAILED",
                    currentUser.getEmail(),
                    "MEDIUM",
                    String.format("Échec suppression groupe ID: %d - %s", roleGroupId, e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Nettoyer les assignations de groupes expirées
     */
    @Transactional
    public int cleanupExpiredRoleGroups() {
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            List<UserRoleGroup> expiredRoleGroups = userRoleGroupRepository.findExpiredUserRoleGroups(LocalDateTime.now());
            int count = 0;

            for (UserRoleGroup userRoleGroup : expiredRoleGroups) {
                userRoleGroup.setIsActive(false);
                userRoleGroupRepository.save(userRoleGroup);
                count++;

                // AUDIT par groupe expiré
                auditClient.logAuditEvent(
                        "ROLE_GROUP_EXPIRED_AUTOMATIC",
                        "system",
                        String.format("Groupe de rôles expiré automatiquement: %s de %s (expiré le: %s)",
                                userRoleGroup.getRoleGroup().getName(),
                                userRoleGroup.getUser().getEmail(),
                                userRoleGroup.getExpiresAt()),
                        httpRequest,
                        0L
                );
            }

            if (count > 0) {
                auditClient.logAuditEvent(
                        "EXPIRED_ROLE_GROUPS_CLEANUP_COMPLETED",
                        "system",
                        String.format("Nettoyage automatique: %d groupes de rôles expirés désactivés", count),
                        httpRequest,
                        0L
                );
            }

            log.info("🧹 Nettoyage des groupes de rôles expirés: {} groupes désactivés", count);
            return count;

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "EXPIRED_ROLE_GROUPS_CLEANUP_FAILED",
                    "system",
                    "MEDIUM",
                    "Échec nettoyage groupes de rôles expirés: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    private RoleGroupDto mapToRoleGroupDto(RoleGroup roleGroup) {
        List<RoleDto> roles = roleGroup.getRoles().stream()
                .map(this::mapToBasicRoleDto)
                .collect(Collectors.toList());

        Long activeUsersCount = roleGroupRepository.countActiveUsersByRoleGroup(roleGroup.getId());

        return RoleGroupDto.builder()
                .id(roleGroup.getId())
                .name(roleGroup.getName())
                .description(roleGroup.getDescription())
                .isActive(roleGroup.getIsActive())
                .isDefault(roleGroup.getIsDefault())
                .createdBy(roleGroup.getCreatedBy())
                .updatedBy(roleGroup.getUpdatedBy())
                .createdAt(roleGroup.getCreatedAt())
                .updatedAt(roleGroup.getUpdatedAt())
                .roles(roles)
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
                .priority(role.getPriority())
                .build();
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
}