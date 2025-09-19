package com.example.security.services;

import com.example.security.entites.*;
import com.example.security.repositories.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleInitializationService implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RoleGroupRepository roleGroupRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        log.info("🚀 Initialisation du système de gestion des rôles...");

        try {
            initializeSystemPermissions();
            initializeSystemRoles();
            initializeDefaultRoleGroups();
            updateExistingUsers();

            log.info("✅ Système de gestion des rôles initialisé avec succès");
        } catch (Exception e) {
            log.error("❌ Erreur lors de l'initialisation du système de rôles", e);
            throw e;
        }
    }

    /**
     * Initialise les permissions système de base
     */
    private void initializeSystemPermissions() {
        log.info("📝 Initialisation des permissions système...");

        List<SystemPermission> systemPermissions = Arrays.asList(
                // Permissions utilisateur
                new SystemPermission("USER_READ", "USER", "READ", "Lire les informations utilisateur"),
                new SystemPermission("USER_WRITE", "USER", "WRITE", "Modifier les informations utilisateur"),
                new SystemPermission("USER_DELETE", "USER", "DELETE", "Supprimer un utilisateur"),
                new SystemPermission("USER_CREATE", "USER", "CREATE", "Créer un utilisateur"),

                // Permissions rôles
                new SystemPermission("ROLE_READ", "ROLE", "READ", "Lire les rôles"),
                new SystemPermission("ROLE_WRITE", "ROLE", "WRITE", "Modifier les rôles"),
                new SystemPermission("ROLE_DELETE", "ROLE", "DELETE", "Supprimer les rôles"),
                new SystemPermission("ROLE_CREATE", "ROLE", "CREATE", "Créer des rôles"),
                new SystemPermission("ROLE_ASSIGN", "ROLE", "ASSIGN", "Assigner des rôles"),
                new SystemPermission("ROLE_REVOKE", "ROLE", "REVOKE", "Révoquer des rôles"),

                // Permissions permissions
                new SystemPermission("PERMISSION_READ", "PERMISSION", "READ", "Lire les permissions"),
                new SystemPermission("PERMISSION_WRITE", "PERMISSION", "WRITE", "Modifier les permissions"),
                new SystemPermission("PERMISSION_DELETE", "PERMISSION", "DELETE", "Supprimer les permissions"),
                new SystemPermission("PERMISSION_CREATE", "PERMISSION", "CREATE", "Créer des permissions"),

                // Permissions système
                new SystemPermission("SYSTEM_ADMIN", "SYSTEM", "ADMIN", "Administration système complète"),
                new SystemPermission("SYSTEM_AUDIT", "SYSTEM", "AUDIT", "Accès aux logs d'audit"),
                new SystemPermission("SYSTEM_CONFIG", "SYSTEM", "CONFIG", "Configuration système"),
                new SystemPermission("SYSTEM_MAINTENANCE", "SYSTEM", "MAINTENANCE", "Maintenance système"),

                // Permissions analytics
                new SystemPermission("ANALYTICS_READ", "ANALYTICS", "READ", "Consulter les analytics"),
                new SystemPermission("ANALYTICS_EXPORT", "ANALYTICS", "EXPORT", "Exporter les données analytics"),

                // Permissions notifications
                new SystemPermission("NOTIFICATION_READ", "NOTIFICATION", "READ", "Lire les notifications"),
                new SystemPermission("NOTIFICATION_SEND", "NOTIFICATION", "SEND", "Envoyer des notifications"),

                // Permissions sessions
                new SystemPermission("SESSION_READ", "SESSION", "READ", "Consulter les sessions"),
                new SystemPermission("SESSION_MANAGE", "SESSION", "MANAGE", "Gérer les sessions utilisateurs")
        );

        for (SystemPermission sp : systemPermissions) {
            if (!permissionRepository.existsByName(sp.name)) {
                Permission permission = Permission.builder()
                        .name(sp.name)
                        .resource(sp.resource)
                        .action(sp.action)
                        .description(sp.description)
                        .isActive(true)
                        .isSystem(true)
                        .createdBy("SYSTEM")
                        .build();

                permissionRepository.save(permission);
                log.debug("Permission créée: {}", sp.name);
            }
        }

        log.info("✅ {} permissions système initialisées", systemPermissions.size());
    }

    /**
     * Initialise les rôles système de base
     */
    private void initializeSystemRoles() {
        log.info("👥 Initialisation des rôles système...");

        // Super Admin - Tous les droits
        createSystemRoleIfNotExists("SUPER_ADMIN", "SYSTEM", "Super Administrateur avec tous les droits", 1000,
                Arrays.asList("SYSTEM_ADMIN", "SYSTEM_AUDIT", "SYSTEM_CONFIG", "SYSTEM_MAINTENANCE",
                        "USER_READ", "USER_WRITE", "USER_DELETE", "USER_CREATE",
                        "ROLE_READ", "ROLE_WRITE", "ROLE_DELETE", "ROLE_CREATE", "ROLE_ASSIGN", "ROLE_REVOKE",
                        "PERMISSION_READ", "PERMISSION_WRITE", "PERMISSION_DELETE", "PERMISSION_CREATE",
                        "ANALYTICS_READ", "ANALYTICS_EXPORT", "NOTIFICATION_READ", "NOTIFICATION_SEND",
                        "SESSION_READ", "SESSION_MANAGE"));

        // Admin - Gestion des utilisateurs et rôles
        createSystemRoleIfNotExists("ADMIN", "SYSTEM", "Administrateur système", 900,
                Arrays.asList("USER_READ", "USER_WRITE", "USER_DELETE", "USER_CREATE",
                        "ROLE_READ", "ROLE_WRITE", "ROLE_DELETE", "ROLE_CREATE", "ROLE_ASSIGN", "ROLE_REVOKE",
                        "PERMISSION_READ", "ANALYTICS_READ", "NOTIFICATION_READ", "NOTIFICATION_SEND",
                        "SESSION_READ", "SESSION_MANAGE"));

        // Role Manager - Gestion des rôles uniquement
        createSystemRoleIfNotExists("ROLE_MANAGER", "BUSINESS", "Gestionnaire de rôles", 500,
                Arrays.asList("ROLE_READ", "ROLE_WRITE", "ROLE_CREATE", "ROLE_ASSIGN", "ROLE_REVOKE",
                        "PERMISSION_READ", "USER_READ", "ANALYTICS_READ"));

        // User Manager - Gestion des utilisateurs
        createSystemRoleIfNotExists("USER_MANAGER", "BUSINESS", "Gestionnaire d'utilisateurs", 400,
                Arrays.asList("USER_READ", "USER_WRITE", "USER_CREATE", "ROLE_READ", "ROLE_ASSIGN"));

        // Auditor - Lecture seule des logs et analytics
        createSystemRoleIfNotExists("AUDITOR", "FUNCTIONAL", "Auditeur - lecture seule", 300,
                Arrays.asList("SYSTEM_AUDIT", "ANALYTICS_READ", "USER_READ", "ROLE_READ", "PERMISSION_READ"));

        // User - Rôle utilisateur standard
        createSystemRoleIfNotExists("USER", "FUNCTIONAL", "Utilisateur standard", 100,
                Arrays.asList("USER_READ", "NOTIFICATION_READ", "SESSION_READ"));

        // Guest - Visiteur avec droits très limités
        createSystemRoleIfNotExists("GUEST", "FUNCTIONAL", "Visiteur avec droits limités", 50,
                Arrays.asList());

        log.info("✅ Rôles système initialisés");
    }

    /**
     * Initialise les groupes de rôles par défaut
     */
    private void initializeDefaultRoleGroups() {
        log.info("🏷️ Initialisation des groupes de rôles par défaut...");

        // Groupe Administrateurs
        createRoleGroupIfNotExists("ADMINISTRATORS", "Groupe des administrateurs système", false,
                Arrays.asList("SUPER_ADMIN", "ADMIN"));

        // Groupe Gestionnaires
        createRoleGroupIfNotExists("MANAGERS", "Groupe des gestionnaires", false,
                Arrays.asList("ROLE_MANAGER", "USER_MANAGER"));

        // Groupe Utilisateurs Standards (par défaut)
        createRoleGroupIfNotExists("STANDARD_USERS", "Groupe des utilisateurs standards", true,
                Arrays.asList("USER"));

        // Groupe Auditeurs
        createRoleGroupIfNotExists("AUDITORS", "Groupe des auditeurs", false,
                Arrays.asList("AUDITOR"));

        log.info("✅ Groupes de rôles par défaut initialisés");
    }

    /**
     * Met à jour les utilisateurs existants avec les nouveaux rôles
     */
    private void updateExistingUsers() {
        log.info("🔄 Mise à jour des utilisateurs existants...");

        List<User> existingUsers = userRepository.findAll();
        int updatedCount = 0;

        for (User user : existingUsers) {
            boolean needsUpdate = false;

            // Convertir les anciens rôles TypeRoles vers les nouveaux rôles
            if (user.getRoles() != null) {
                Role newRole = null;

                switch (user.getRoles()) {
                    case ADMIN:
                        newRole = roleRepository.findByName("ADMIN").orElse(null);
                        break;
                    case USER:
                        newRole = roleRepository.findByName("USER").orElse(null);
                        break;
                }

                if (newRole != null) {
                    // Créer une assignation de rôle si elle n'existe pas
                    if (!userRoleRepository.existsByUserAndRole(user, newRole)) {
                        UserRole userRole = UserRole.builder()
                                .user(user)
                                .role(newRole)
                                .isActive(true)
                                .assignedBy("SYSTEM")
                                .assignmentReason("Migration automatique des rôles")
                                .build();

                        userRoleRepository.save(userRole);
                        updatedCount++;
                        needsUpdate = true;
                    }
                }
            }

            if (needsUpdate) {
                log.debug("Utilisateur mis à jour: {}", user.getEmail());
            }
        }

        log.info("✅ {} utilisateurs mis à jour avec les nouveaux rôles", updatedCount);
    }

    private void createSystemRoleIfNotExists(String name, String category, String description,
                                             int priority, List<String> permissionNames) {

        if (!roleRepository.existsByName(name)) {
            Role role = Role.builder()
                    .name(name)
                    .description(description)
                    .category(category)
                    .priority(priority)
                    .isActive(true)
                    .isSystem(true)
                    .createdBy("SYSTEM")
                    .build();

            // Ajouter les permissions
            Set<Permission> permissions = new HashSet<>();
            for (String permissionName : permissionNames) {
                permissionRepository.findByName(permissionName)
                        .ifPresent(permissions::add);
            }
            role.setPermissions(permissions);

            roleRepository.save(role);
            log.debug("Rôle système créé: {} avec {} permissions", name, permissions.size());
        }
    }

    private void createRoleGroupIfNotExists(String name, String description, boolean isDefault,
                                            List<String> roleNames) {

        if (!roleGroupRepository.existsByName(name)) {
            RoleGroup roleGroup = RoleGroup.builder()
                    .name(name)
                    .description(description)
                    .isActive(true)
                    .isDefault(isDefault)
                    .createdBy("SYSTEM")
                    .build();

            // Ajouter les rôles
            Set<Role> roles = new HashSet<>();
            for (String roleName : roleNames) {
                roleRepository.findByName(roleName)
                        .ifPresent(roles::add);
            }
            roleGroup.setRoles(roles);

            roleGroupRepository.save(roleGroup);
            log.debug("Groupe de rôles créé: {} avec {} rôles", name, roles.size());
        }
    }

    /**
     * Classe interne pour définir les permissions système
     */
    private static class SystemPermission {
        final String name;
        final String resource;
        final String action;
        final String description;

        SystemPermission(String name, String resource, String action, String description) {
            this.name = name;
            this.resource = resource;
            this.action = action;
            this.description = description;
        }
    }
}
