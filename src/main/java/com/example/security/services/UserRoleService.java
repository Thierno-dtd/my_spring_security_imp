package com.example.security.services;

import com.example.security.dto.*;
import com.example.security.entites.*;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.outils.DataEncryption;
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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserRoleService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleExclusionRepository roleExclusionRepository;
    private final RoleDependencyRepository roleDependencyRepository;
    private final AuditMicroserviceClient auditClient;
    private final NotificationClient notificationClient;
    private final AuthenticationService authenticationService;
    private final DataEncryption dataEncryption;
    private final RoleService roleService;

    /**
     * Assigner un rôle à un utilisateur
     */
    @Transactional
    public UserRoleDto assignRole(AssignRoleRequest request) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            User user = userRepository.findById(request.getUserId())
                    .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + request.getUserId()));

            Role role = roleRepository.findById(request.getRoleId())
                    .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + request.getRoleId()));

            // Vérifier si l'assignation existe déjà
            if (userRoleRepository.existsByUserAndRole(user, role)) {
                throw new IllegalArgumentException(
                        String.format("L'utilisateur %s possède déjà le rôle %s", user.getEmail(), role.getName()));
            }

            // Valider les conflits et dépendances
            List<UserRole> currentUserRoles = userRoleRepository.findEffectiveUserRoles(user, LocalDateTime.now());
            List<Long> currentRoleIds = currentUserRoles.stream()
                    .map(ur -> ur.getRole().getId())
                    .collect(Collectors.toList());

            List<Long> newRoleIds = new ArrayList<>(currentRoleIds);
            newRoleIds.add(request.getRoleId());

            RoleValidationResultDto validation = roleService.validateUserRoles(user.getId(), newRoleIds);
            if (!validation.getIsValid() && !validation.getConflicts().isEmpty()) {
                throw new IllegalArgumentException("Conflit détecté: " + validation.getSummary());
            }

            // Créer l'assignation
            UserRole userRole = UserRole.builder()
                    .user(user)
                    .role(role)
                    .isActive(true)
                    .expiresAt(request.getExpiresAt())
                    .assignedBy(currentUser.getEmail())
                    .assignmentReason(request.getAssignmentReason())
                    .build();

            userRole = userRoleRepository.save(userRole);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_ASSIGNED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Rôle assigné: %s à %s (utilisateur ID: %d). Expire: %s. Raison: %s",
                            role.getName(), user.getEmail(), user.getId(),
                            request.getExpiresAt(), request.getAssignmentReason()),
                    httpRequest,
                    0L
            );

            // Envoyer notification si demandé
            if (request.getSendNotification()) {
                try {
                    String decryptedName = dataEncryption.decryptSensitiveData(user.getName());
                    notificationClient.sendRoleAssignmentNotification(
                            user.getEmail(),
                            decryptedName,
                            role.getName(),
                            request.getExpiresAt(),
                            currentUser.getEmail()
                    );
                } catch (Exception e) {
                    log.warn("Échec envoi notification assignation rôle: {}", e.getMessage());
                }
            }

            log.info("✅ Rôle {} assigné à {} par {}", role.getName(), user.getEmail(), currentUser.getEmail());

            return mapToUserRoleDto(userRole);

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_ASSIGNMENT_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Échec assignation rôle ID %d à utilisateur ID %d: %s",
                            request.getRoleId(), request.getUserId(), e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Assignation en masse de rôles
     */
    @Transactional
    public RoleAssignmentResultDto bulkAssignRole(BulkRoleAssignmentRequest request) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        List<String> successfulAssignments = new ArrayList<>();
        List<String> failedAssignments = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        try {
            Role role = roleRepository.findById(request.getRoleId())
                    .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + request.getRoleId()));

            for (Long userId : request.getUserIds()) {
                try {
                    AssignRoleRequest singleRequest = AssignRoleRequest.builder()
                            .userId(userId)
                            .roleId(request.getRoleId())
                            .expiresAt(request.getExpiresAt())
                            .assignmentReason(request.getAssignmentReason())
                            .sendNotification(request.getSendNotifications())
                            .build();

                    assignRole(singleRequest);

                    User user = userRepository.findById(userId).orElse(null);
                    String userEmail = user != null ? user.getEmail() : "ID:" + userId;
                    successfulAssignments.add(userEmail);

                } catch (Exception e) {
                    User user = userRepository.findById(userId).orElse(null);
                    String userEmail = user != null ? user.getEmail() : "ID:" + userId;
                    failedAssignments.add(userEmail + " (" + e.getMessage() + ")");
                }
            }

            // AUDIT global
            auditClient.logAuditEvent(
                    "BULK_ROLE_ASSIGNMENT_COMPLETED",
                    currentUser.getEmail(),
                    String.format("Assignation en masse rôle %s: %d succès, %d échecs",
                            role.getName(), successfulAssignments.size(), failedAssignments.size()),
                    httpRequest,
                    0L
            );

            return RoleAssignmentResultDto.builder()
                    .successCount(successfulAssignments.size())
                    .failureCount(failedAssignments.size())
                    .successfulAssignments(successfulAssignments)
                    .failedAssignments(failedAssignments)
                    .warnings(warnings)
                    .summary(String.format("Assignation terminée: %d succès, %d échecs",
                            successfulAssignments.size(), failedAssignments.size()))
                    .build();

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "BULK_ROLE_ASSIGNMENT_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    "Échec assignation en masse: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Révoquer un rôle d'un utilisateur
     */
    @Transactional
    public void revokeRole(Long userId, Long roleId, String reason) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + userId));

            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + roleId));

            UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                    .orElseThrow(() -> new EntityNotFoundException(
                            String.format("L'utilisateur %s ne possède pas le rôle %s", user.getEmail(), role.getName())));

            if (!userRole.getIsActive()) {
                throw new IllegalArgumentException("Ce rôle est déjà inactif pour cet utilisateur");
            }

            userRole.setIsActive(false);
            userRole.setRevokedBy(currentUser.getEmail());
            userRole.setRevocationReason(reason);
            userRole.setRevokedAt(LocalDateTime.now());
            userRoleRepository.save(userRole);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_REVOKED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Rôle révoqué: %s de %s (utilisateur ID: %d). Raison: %s",
                            role.getName(), user.getEmail(), user.getId(), reason),
                    httpRequest,
                    0L
            );

            // Notification
            try {
                String decryptedName = dataEncryption.decryptSensitiveData(user.getName());
                notificationClient.sendRoleRevocationNotification(
                        user.getEmail(),
                        decryptedName,
                        role.getName(),
                        reason,
                        currentUser.getEmail()
                );
            } catch (Exception e) {
                log.warn("Échec envoi notification révocation rôle: {}", e.getMessage());
            }

            log.info("✅ Rôle {} révoqué de {} par {}", role.getName(), user.getEmail(), currentUser.getEmail());

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_REVOCATION_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Échec révocation rôle ID %d de l'utilisateur ID %d: %s", roleId, userId, e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Révoquer en masse un rôle de plusieurs utilisateurs
     */
    @Transactional
    public RoleRevocationResultDto bulkRevokeRole(BulkRoleRevocationRequest request) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        List<String> successfulRevocations = new ArrayList<>();
        List<String> failedRevocations = new ArrayList<>();

        try {
            Role role = roleRepository.findById(request.getRoleId())
                    .orElseThrow(() -> new EntityNotFoundException("Rôle non trouvé: " + request.getRoleId()));

            for (Long userId : request.getUserIds()) {
                try {
                    revokeRole(userId, request.getRoleId(), request.getRevocationReason());

                    User user = userRepository.findById(userId).orElse(null);
                    String userEmail = user != null ? user.getEmail() : "ID:" + userId;
                    successfulRevocations.add(userEmail);

                } catch (Exception e) {
                    User user = userRepository.findById(userId).orElse(null);
                    String userEmail = user != null ? user.getEmail() : "ID:" + userId;
                    failedRevocations.add(userEmail + " (" + e.getMessage() + ")");
                }
            }

            // AUDIT global
            auditClient.logAuditEvent(
                    "BULK_ROLE_REVOCATION_COMPLETED",
                    currentUser.getEmail(),
                    String.format("Révocation en masse rôle %s: %d succès, %d échecs",
                            role.getName(), successfulRevocations.size(), failedRevocations.size()),
                    httpRequest,
                    0L
            );

            return RoleRevocationResultDto.builder()
                    .successCount(successfulRevocations.size())
                    .failureCount(failedRevocations.size())
                    .successfulRevocations(successfulRevocations)
                    .failedRevocations(failedRevocations)
                    .summary(String.format("Révocation terminée: %d succès, %d échecs",
                            successfulRevocations.size(), failedRevocations.size()))
                    .build();

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "BULK_ROLE_REVOCATION_FAILED",
                    currentUser.getEmail(),
                    "HIGH",
                    "Échec révocation en masse: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Obtenir les rôles d'un utilisateur avec pagination
     */
    public PagedResponse<UserRoleDto> getUserRoles(Long userId, int page, int size, String sortBy, String sortDir, Boolean includeExpired) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + userId));

        Pageable pageable = PageRequest.of(page, size,
                sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending());

        Page<UserRole> userRolesPage;
        if (includeExpired != null && includeExpired) {
            userRolesPage = userRoleRepository.findByUserAndIsActiveTrue(user, pageable);
        } else {
            userRolesPage = userRoleRepository.findEffectiveUserRoles(user, LocalDateTime.now(), pageable);
        }

        List<UserRoleDto> userRoleDtos = userRolesPage.getContent().stream()
                .map(this::mapToUserRoleDto)
                .collect(Collectors.toList());

        return PagedResponse.<UserRoleDto>builder()
                .content(userRoleDtos)
                .page(page)
                .size(size)
                .totalElements(userRolesPage.getTotalElements())
                .totalPages(userRolesPage.getTotalPages())
                .first(userRolesPage.isFirst())
                .last(userRolesPage.isLast())
                .hasNext(userRolesPage.hasNext())
                .hasPrevious(userRolesPage.hasPrevious())
                .build();
    }

    /**
     * Obtenir les rôles d'un utilisateur (version simple)
     */
    public List<UserRoleDto> getUserRoles(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + userId));

        return userRoleRepository.findByUserAndIsActiveTrue(user).stream()
                .map(this::mapToUserRoleDto)
                .collect(Collectors.toList());
    }

    /**
     * Obtenir les rôles effectifs d'un utilisateur (non expirés)
     */
    public List<UserRoleDto> getEffectiveUserRoles(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + userId));

        return userRoleRepository.findEffectiveUserRoles(user, LocalDateTime.now()).stream()
                .map(this::mapToUserRoleDto)
                .collect(Collectors.toList());
    }

    /**
     * Prolonger l'expiration d'un rôle
     */
    @Transactional
    public UserRoleDto extendRoleExpiration(Long userRoleId, LocalDateTime newExpirationDate, String reason) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            UserRole userRole = userRoleRepository.findById(userRoleId)
                    .orElseThrow(() -> new EntityNotFoundException("Attribution de rôle non trouvée: " + userRoleId));

            LocalDateTime oldExpiration = userRole.getExpiresAt();
            userRole.setExpiresAt(newExpirationDate);
            userRole.setUpdatedBy(currentUser.getEmail());
            userRole = userRoleRepository.save(userRole);

            // AUDIT
            auditClient.logAuditEvent(
                    "ROLE_EXPIRATION_EXTENDED",
                    currentUser.getEmail(),
                    String.format("Extension expiration rôle %s pour %s. Ancienne: %s, Nouvelle: %s. Raison: %s",
                            userRole.getRole().getName(), userRole.getUser().getEmail(),
                            oldExpiration, newExpirationDate, reason),
                    httpRequest,
                    0L
            );

            return mapToUserRoleDto(userRole);

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "ROLE_EXTENSION_FAILED",
                    currentUser.getEmail(),
                    "MEDIUM",
                    String.format("Échec extension rôle ID %d: %s", userRoleId, e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Nettoyer les rôles expirés
     */
    @Transactional
    public int cleanupExpiredRoles() {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            List<UserRole> expiredRoles = userRoleRepository.findExpiredUserRoles(LocalDateTime.now());
            int count = 0;

            for (UserRole userRole : expiredRoles) {
                userRole.setIsActive(false);
                userRole.setRevokedBy("system");
                userRole.setRevocationReason("Expiration automatique");
                userRole.setRevokedAt(LocalDateTime.now());
                userRoleRepository.save(userRole);
                count++;

                // AUDIT par rôle expiré
                auditClient.logAuditEvent(
                        "ROLE_EXPIRED_AUTOMATIC",
                        "system",
                        String.format("Rôle expiré automatiquement: %s de %s (expiré le: %s)",
                                userRole.getRole().getName(),
                                userRole.getUser().getEmail(),
                                userRole.getExpiresAt()),
                        httpRequest,
                        0L
                );
            }

            if (count > 0) {
                auditClient.logAuditEvent(
                        "EXPIRED_ROLES_CLEANUP_COMPLETED",
                        "system",
                        String.format("Nettoyage automatique: %d rôles expirés désactivés", count),
                        httpRequest,
                        0L
                );
            }

            log.info("🧹 Nettoyage des rôles expirés: {} rôles désactivés", count);
            return count;

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "EXPIRED_ROLES_CLEANUP_FAILED",
                    "system",
                    "MEDIUM",
                    "Échec nettoyage rôles expirés: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Obtenir un rapport des rôles par utilisateur
     */
    public UserRoleReportDto getUserRoleReport(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + userId));

        List<UserRole> activeRoles = userRoleRepository.findByUserAndIsActiveTrue(user);
        List<UserRole> effectiveRoles = userRoleRepository.findEffectiveUserRoles(user, LocalDateTime.now());
        List<UserRole> expiredRoles = userRoleRepository.findExpiredUserRolesByUser(user, LocalDateTime.now());

        return UserRoleReportDto.builder()
                .userId(userId)
                .userEmail(user.getEmail())
                .totalActiveRoles(activeRoles.size())
                .totalEffectiveRoles(effectiveRoles.size())
                .totalExpiredRoles(expiredRoles.size())
                .activeRoles(activeRoles.stream().map(this::mapToUserRoleDto).collect(Collectors.toList()))
                .effectiveRoles(effectiveRoles.stream().map(this::mapToUserRoleDto).collect(Collectors.toList()))
                .expiredRoles(expiredRoles.stream().map(this::mapToUserRoleDto).collect(Collectors.toList()))
                .generatedAt(LocalDateTime.now())
                .build();
    }

    private UserRoleDto mapToUserRoleDto(UserRole userRole) {
        String decryptedUserName = dataEncryption.decryptSensitiveData(userRole.getUser().getName())
                + " " + dataEncryption.decryptSensitiveData(userRole.getUser().getPname());

        return UserRoleDto.builder()
                .id(userRole.getId())
                .userId(userRole.getUser().getId())
                .userEmail(userRole.getUser().getEmail())
                .userName(decryptedUserName)
                .roleId(userRole.getRole().getId())
                .roleName(userRole.getRole().getName())
                .roleDescription(userRole.getRole().getDescription())
                .roleCategory(userRole.getRole().getCategory())
                .isActive(userRole.getIsActive())
                .isTemporary(userRole.isTemporary())
                .isExpired(userRole.isExpired())
                .expiresAt(userRole.getExpiresAt())
                .assignedBy(userRole.getAssignedBy())
                .assignmentReason(userRole.getAssignmentReason())
                .assignedAt(userRole.getAssignedAt())
                .revokedBy(userRole.getRevokedBy())
                .revocationReason(userRole.getRevocationReason())
                .revokedAt(userRole.getRevokedAt())
                .updatedBy(userRole.getUpdatedBy())
                .updatedAt(userRole.getUpdatedAt())
                .build();
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
}