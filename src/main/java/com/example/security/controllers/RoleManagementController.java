package com.example.security.controllers;

import com.example.security.dto.*;
import com.example.security.services.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.security.constants.utils.APP_ROOT;

@RestController
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@RequestMapping(APP_ROOT + "/roles")
@Slf4j
@Tag(name = "Role Management", description = "Gestion complète des rôles, permissions, groupes de rôles et assignations")
public class RoleManagementController {

    private final RoleService roleService;
    private final PermissionService permissionService;
    private final UserRoleService userRoleService;
    private final RoleGroupService roleGroupService;
    private final RoleAnalyticsService roleAnalyticsService;

    // =============== GESTION DES RÔLES ===============

    @Operation(
            summary = "Créer un nouveau rôle",
            description = "Crée un nouveau rôle avec ses permissions, exclusions et dépendances"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Rôle créé avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "403", description = "Accès refusé")
    })
    @PostMapping("/create")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleDto> createRole(@Valid @RequestBody CreateRoleRequest request) {
        RoleDto role = roleService.createRole(request);
        return ResponseEntity.ok(role);
    }

    @Operation(
            summary = "Mettre à jour un rôle",
            description = "Met à jour les propriétés d'un rôle existant"
    )
    @PutMapping("/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleDto> updateRole(
            @PathVariable Long roleId,
            @Valid @RequestBody UpdateRoleRequest request) {
        RoleDto role = roleService.updateRole(roleId, request);
        return ResponseEntity.ok(role);
    }

    @Operation(
            summary = "Supprimer un rôle",
            description = "Supprime un rôle s'il n'est pas utilisé par des utilisateurs"
    )
    @DeleteMapping("/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<Map<String, String>> deleteRole(
            @PathVariable Long roleId,
            @RequestParam(required = false) String reason) {
        roleService.deleteRole(roleId, reason != null ? reason : "Suppression demandée par l'admin");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Rôle supprimé avec succès");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Obtenir tous les rôles",
            description = "Récupère la liste paginée de tous les rôles avec possibilité de recherche"
    )
    @GetMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<PagedResponse<RoleDto>> getAllRoles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestParam(required = false) String search) {
        PagedResponse<RoleDto> roles = roleService.getAllRoles(page, size, sortBy, sortDir, search);
        return ResponseEntity.ok(roles);
    }

    @Operation(
            summary = "Obtenir un rôle par ID",
            description = "Récupère les détails complets d'un rôle spécifique"
    )
    @GetMapping("/{roleId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleDto> getRoleById(@PathVariable Long roleId) {
        RoleDto role = roleService.getRoleById(roleId);
        return ResponseEntity.ok(role);
    }

    @Operation(
            summary = "Obtenir les rôles par catégorie",
            description = "Récupère tous les rôles d'une catégorie spécifique"
    )
    @GetMapping("/category/{category}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<RoleDto>> getRolesByCategory(@PathVariable String category) {
        List<RoleDto> roles = roleService.getRolesByCategory(category);
        return ResponseEntity.ok(roles);
    }

    @Operation(
            summary = "Valider l'assignation de rôles",
            description = "Valide qu'une liste de rôles peut être assignée à un utilisateur sans conflit"
    )
    @PostMapping("/validate")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleValidationResultDto> validateUserRoles(
            @RequestParam Long userId,
            @RequestBody List<Long> roleIds) {
        RoleValidationResultDto validation = roleService.validateUserRoles(userId, roleIds);
        return ResponseEntity.ok(validation);
    }

    // =============== GESTION DES PERMISSIONS ===============
    @Operation(
            summary = "Créer une nouvelle permission",
            description = "Crée une nouvelle permission pour une ressource et une action"
    )
    @PostMapping("/permissions/create")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<PermissionDto> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        PermissionDto permission = permissionService.createPermission(request);
        return ResponseEntity.ok(permission);
    }

    @Operation(
            summary = "Obtenir toutes les permissions",
            description = "Récupère la liste paginée de toutes les permissions"
    )
    @GetMapping("/permissions")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<PagedResponse<PermissionDto>> getAllPermissions(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestParam(required = false) String search) {
        PagedResponse<PermissionDto> permissions = permissionService.getAllPermissions(page, size, sortBy, sortDir, search);
        return ResponseEntity.ok(permissions);
    }

    @Operation(
            summary = "Obtenir les ressources disponibles",
            description = "Récupère la liste de toutes les ressources disponibles pour les permissions"
    )
    @GetMapping("/permissions/resources")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<String>> getAvailableResources() {
        List<String> resources = permissionService.getAvailableResources();
        return ResponseEntity.ok(resources);
    }

    @Operation(
            summary = "Obtenir les actions disponibles",
            description = "Récupère la liste de toutes les actions disponibles pour les permissions"
    )
    @GetMapping("/permissions/actions")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<String>> getAvailableActions() {
        List<String> actions = permissionService.getAvailableActions();
        return ResponseEntity.ok(actions);
    }

    @Operation(
            summary = "Supprimer une permission",
            description = "Supprime une permission si elle n'est pas utilisée"
    )
    @DeleteMapping("/permissions/{permissionId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<Map<String, String>> deletePermission(
            @PathVariable Long permissionId,
            @RequestParam(required = false) String reason) {
        permissionService.deletePermission(permissionId, reason != null ? reason : "Suppression demandée par l'admin");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Permission supprimée avec succès");
        return ResponseEntity.ok(response);
    }

    // =============== ASSIGNATION DE RÔLES AUX UTILISATEURS ===============

    @Operation(
            summary = "Assigner un rôle à un utilisateur",
            description = "Assigne un rôle spécifique à un utilisateur avec possibilité d'expiration"
    )
    @PostMapping("/assign")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<UserRoleDto> assignRole(@Valid @RequestBody AssignRoleRequest request) {
        UserRoleDto userRole = userRoleService.assignRole(request);
        return ResponseEntity.ok(userRole);
    }

    @Operation(
            summary = "Assignation en masse de rôles",
            description = "Assigne un rôle à plusieurs utilisateurs simultanément"
    )
    @PostMapping("/assign/bulk")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleAssignmentResultDto> bulkAssignRole(@Valid @RequestBody BulkRoleAssignmentRequest request) {
        RoleAssignmentResultDto result = userRoleService.bulkAssignRole(request);
        return ResponseEntity.ok(result);
    }

    @Operation(
            summary = "Révoquer un rôle d'un utilisateur",
            description = "Retire un rôle spécifique d'un utilisateur"
    )
    @PostMapping("/revoke")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<Map<String, String>> revokeRole(
            @RequestParam Long userId,
            @RequestParam Long roleId,
            @RequestParam(required = false) String reason) {
        userRoleService.revokeRole(userId, roleId, reason != null ? reason : "Révocation demandée par l'admin");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Rôle révoqué avec succès");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Obtenir les rôles d'un utilisateur",
            description = "Récupère tous les rôles assignés à un utilisateur spécifique"
    )
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<UserRoleDto>> getUserRoles(@PathVariable Long userId) {
        List<UserRoleDto> userRoles = userRoleService.getUserRoles(userId);
        return ResponseEntity.ok(userRoles);
    }

    @Operation(
            summary = "Obtenir les rôles effectifs d'un utilisateur",
            description = "Récupère les rôles actifs et non expirés d'un utilisateur"
    )
    @GetMapping("/user/{userId}/effective")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<UserRoleDto>> getEffectiveUserRoles(@PathVariable Long userId) {
        List<UserRoleDto> effectiveRoles = userRoleService.getEffectiveUserRoles(userId);
        return ResponseEntity.ok(effectiveRoles);
    }

    @Operation(
            summary = "Nettoyer les rôles expirés",
            description = "Désactive automatiquement tous les rôles expirés"
    )
    @PostMapping("/cleanup/expired")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> cleanupExpiredRoles() {
        int cleanedCount = userRoleService.cleanupExpiredRoles();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Nettoyage des rôles expirés terminé");
        response.put("cleanedCount", cleanedCount);
        return ResponseEntity.ok(response);
    }

    // =============== GESTION DES GROUPES DE RÔLES ===============

    @Operation(
            summary = "Créer un nouveau groupe de rôles",
            description = "Crée un nouveau groupe contenant plusieurs rôles"
    )
    @PostMapping("/groups/create")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleGroupDto> createRoleGroup(@Valid @RequestBody CreateRoleGroupRequest request) {
        RoleGroupDto roleGroup = roleGroupService.createRoleGroup(request);
        return ResponseEntity.ok(roleGroup);
    }

    @Operation(
            summary = "Obtenir tous les groupes de rôles",
            description = "Récupère la liste paginée de tous les groupes de rôles"
    )
    @GetMapping("/groups")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<PagedResponse<RoleGroupDto>> getAllRoleGroups(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestParam(required = false) String search) {
        PagedResponse<RoleGroupDto> roleGroups = roleGroupService.getAllRoleGroups(page, size, sortBy, sortDir, search);
        return ResponseEntity.ok(roleGroups);
    }

    @Operation(
            summary = "Assigner un groupe de rôles à un utilisateur",
            description = "Assigne tous les rôles d'un groupe à un utilisateur"
    )
    @PostMapping("/groups/assign")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<Map<String, String>> assignRoleGroupToUser(
            @RequestParam Long userId,
            @RequestParam Long roleGroupId,
            @RequestParam(required = false) String expiresAt,
            @RequestParam(required = false) String reason) {

        LocalDateTime expirationDate = null;
        if (expiresAt != null && !expiresAt.isEmpty()) {
            expirationDate = LocalDateTime.parse(expiresAt);
        }

        roleGroupService.assignRoleGroupToUser(userId, roleGroupId, expirationDate,
                reason != null ? reason : "Assignation de groupe par l'admin");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Groupe de rôles assigné avec succès");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Supprimer un groupe de rôles",
            description = "Supprime un groupe de rôles s'il n'est pas utilisé"
    )
    @DeleteMapping("/groups/{roleGroupId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<Map<String, String>> deleteRoleGroup(
            @PathVariable Long roleGroupId,
            @RequestParam(required = false) String reason) {
        roleGroupService.deleteRoleGroup(roleGroupId, reason != null ? reason : "Suppression demandée par l'admin");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Groupe de rôles supprimé avec succès");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Nettoyer les groupes de rôles expirés",
            description = "Désactive automatiquement tous les groupes de rôles expirés"
    )
    @PostMapping("/groups/cleanup/expired")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> cleanupExpiredRoleGroups() {
        int cleanedCount = roleGroupService.cleanupExpiredRoleGroups();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Nettoyage des groupes de rôles expirés terminé");
        response.put("cleanedCount", cleanedCount);
        return ResponseEntity.ok(response);
    }

    // =============== ANALYTICS ET RAPPORTS ===============

    @Operation(
            summary = "Obtenir les analytics des rôles",
            description = "Fournit des statistiques complètes sur l'utilisation des rôles"
    )
    @GetMapping("/analytics")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RoleAnalyticsDto> getRoleAnalytics() {
        RoleAnalyticsDto analytics = roleAnalyticsService.getRoleAnalytics();
        return ResponseEntity.ok(analytics);
    }

    @Operation(
            summary = "Détecter les conflits de rôles",
            description = "Identifie tous les conflits de rôles existants dans le système"
    )
    @GetMapping("/conflicts")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<RoleConflictDto>> detectRoleConflicts() {
        List<RoleConflictDto> conflicts = roleAnalyticsService.detectRoleConflicts();
        return ResponseEntity.ok(conflicts);
    }

    @Operation(
            summary = "Générer la matrice permissions-rôles",
            description = "Génère une matrice complète montrant quels rôles ont quelles permissions"
    )
    @GetMapping("/permission-matrix")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<RolePermissionMatrixDto> generatePermissionMatrix() {
        RolePermissionMatrixDto matrix = roleAnalyticsService.generatePermissionMatrix();
        return ResponseEntity.ok(matrix);
    }

    // =============== HEALTH CHECK ET DIAGNOSTICS ===============

    @Operation(
            summary = "Health Check du module de rôles",
            description = "Vérifie l'état du service de gestion des rôles"
    )
    @GetMapping("/health")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Role Management Service");
        response.put("timestamp", LocalDateTime.now());
        response.put("features", Map.of(
                "roleManagement", true,
                "permissionManagement", true,
                "userRoleAssignment", true,
                "roleGroups", true,
                "roleAnalytics", true,
                "conflictDetection", true,
                "bulkOperations", true,
                "auditLogging", true,
                "notifications", true,
                "expirationManagement", true
        ));

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Statistiques système des rôles",
            description = "Fournit des informations de diagnostic sur le système de rôles"
    )
    @GetMapping("/system-stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getSystemStats() {
        RoleAnalyticsDto analytics = roleAnalyticsService.getRoleAnalytics();
        List<RoleConflictDto> conflicts = roleAnalyticsService.detectRoleConflicts();

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalRoles", analytics.getTotalRoles());
        stats.put("activeRoles", analytics.getActiveRoles());
        stats.put("totalPermissions", analytics.getTotalPermissions());
        stats.put("totalRoleGroups", analytics.getTotalRoleGroups());
        stats.put("totalAssignments", analytics.getTotalUserRoleAssignments());
        stats.put("expiredAssignments", analytics.getExpiredRoleAssignments());
        stats.put("conflictsDetected", conflicts.size());
        stats.put("systemHealth", conflicts.isEmpty() ? "HEALTHY" : "CONFLICTS_DETECTED");
        stats.put("lastUpdated", LocalDateTime.now());

        return ResponseEntity.ok(stats);
    }

    // =============== ENDPOINTS DE MAINTENANCE ===============

    @Operation(
            summary = "Maintenance globale du système de rôles",
            description = "Exécute toutes les tâches de maintenance automatiques"
    )
    @PostMapping("/maintenance/full")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> performFullMaintenance() {
        Map<String, Object> results = new HashMap<>();

        try {
            // Nettoyer les rôles expirés
            int expiredRoles = userRoleService.cleanupExpiredRoles();
            results.put("expiredRolesCleanup", expiredRoles);

            // Nettoyer les groupes expirés
            int expiredGroups = roleGroupService.cleanupExpiredRoleGroups();
            results.put("expiredGroupsCleanup", expiredGroups);

            // Détecter les conflits
            List<RoleConflictDto> conflicts = roleAnalyticsService.detectRoleConflicts();
            results.put("conflictsDetected", conflicts.size());

            results.put("maintenanceCompleted", LocalDateTime.now());
            results.put("status", "SUCCESS");
            results.put("summary", String.format("Maintenance terminée: %d rôles expirés, %d groupes expirés, %d conflits détectés",
                    expiredRoles, expiredGroups, conflicts.size()));

        } catch (Exception e) {
            results.put("status", "ERROR");
            results.put("error", e.getMessage());
        }

        return ResponseEntity.ok(results);
    }

    @Operation(
            summary = "Recalculer les analytics",
            description = "Force le recalcul de toutes les statistiques et analytics"
    )
    @PostMapping("/maintenance/recalculate-analytics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<RoleAnalyticsDto> recalculateAnalytics() {
        RoleAnalyticsDto analytics = roleAnalyticsService.getRoleAnalytics();
        return ResponseEntity.ok(analytics);
    }
}