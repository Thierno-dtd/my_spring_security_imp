package com.example.security.services;

import com.example.security.dto.*;
import com.example.security.entites.Permission;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.repositories.PermissionRepository;
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

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final AuditMicroserviceClient auditClient;
    private final AuthenticationService authenticationService;

    /**
     * Créer une nouvelle permission
     */
    @Transactional
    public PermissionDto createPermission(CreatePermissionRequest request) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            // Vérifier si la permission existe déjà
            if (permissionRepository.existsByResourceAndAction(request.getResource(), request.getAction())) {
                throw new IllegalArgumentException(
                        String.format("Une permission existe déjà pour la ressource '%s' et l'action '%s'",
                                request.getResource(), request.getAction()));
            }

            String permissionName = request.getName() != null ? request.getName()
                    : request.getResource() + "_" + request.getAction();

            Permission permission = Permission.builder()
                    .name(permissionName)
                    .resource(request.getResource())
                    .action(request.getAction())
                    .description(request.getDescription())
                    .isActive(true)
                    .isSystem(false)
                    .createdBy(currentUser.getEmail())
                    .build();

            permission = permissionRepository.save(permission);

            // AUDIT
            auditClient.logAuditEvent(
                    "PERMISSION_CREATED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Permission créée: %s (ressource: %s, action: %s). Raison: %s",
                            permission.getName(), permission.getResource(), permission.getAction(), request.getReason()),
                    httpRequest,
                    0L
            );

            log.info("✅ Permission créée: {} par {}", permission.getName(), currentUser.getEmail());

            return mapToPermissionDto(permission);

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "PERMISSION_CREATION_FAILED",
                    currentUser.getEmail(),
                    "MEDIUM",
                    String.format("Échec création permission: %s_%s - %s", request.getResource(), request.getAction(), e.getMessage()),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Obtenir toutes les permissions avec pagination
     */
    public PagedResponse<PermissionDto> getAllPermissions(int page, int size, String sortBy, String sortDir, String search) {
        Pageable pageable = PageRequest.of(page, size,
                sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending());

        Page<Permission> permissionsPage;
        if (search != null && !search.trim().isEmpty()) {
            permissionsPage = permissionRepository.findByNameContainingIgnoreCase(search, pageable);
        } else {
            permissionsPage = permissionRepository.findAll(pageable);
        }

        List<PermissionDto> permissionDtos = permissionsPage.getContent().stream()
                .map(this::mapToPermissionDto)
                .collect(Collectors.toList());

        return PagedResponse.<PermissionDto>builder()
                .content(permissionDtos)
                .page(page)
                .size(size)
                .totalElements(permissionsPage.getTotalElements())
                .totalPages(permissionsPage.getTotalPages())
                .first(permissionsPage.isFirst())
                .last(permissionsPage.isLast())
                .hasNext(permissionsPage.hasNext())
                .hasPrevious(permissionsPage.hasPrevious())
                .build();
    }

    /**
     * Obtenir les ressources disponibles
     */
    public List<String> getAvailableResources() {
        return permissionRepository.findAllActiveResources();
    }

    /**
     * Obtenir les actions disponibles
     */
    public List<String> getAvailableActions() {
        return permissionRepository.findAllActiveActions();
    }

    /**
     * Supprimer une permission
     */
    @Transactional
    public void deletePermission(Long permissionId, String reason) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        var currentUser = authenticationService.getCurrentUser();

        try {
            Permission permission = permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new EntityNotFoundException("Permission non trouvée: " + permissionId));

            if (permission.getIsSystem()) {
                throw new IllegalArgumentException("Les permissions système ne peuvent pas être supprimées");
            }

            String permissionName = permission.getName();
            permissionRepository.delete(permission);

            // AUDIT
            auditClient.logAuditEvent(
                    "PERMISSION_DELETED_SUCCESS",
                    currentUser.getEmail(),
                    String.format("Permission supprimée: %s (ID: %d). Raison: %s", permissionName, permissionId, reason),
                    httpRequest,
                    0L
            );

            log.info("✅ Permission supprimée: {} par {}", permissionName, currentUser.getEmail());

        } catch (Exception e) {
            auditClient.logSecurityEvent(
                    "PERMISSION_DELETE_FAILED",
                    currentUser.getEmail(),
                    "MEDIUM",
                    String.format("Échec suppression permission ID: %d - %s", permissionId, e.getMessage()),
                    httpRequest
            );
            throw e;
        }
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