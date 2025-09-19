package com.example.security.services;

import com.example.security.dto.RoleConflictDto;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.module.notifications.NotificationClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleScheduledTasks {

    private final UserRoleService userRoleService;
    private final RoleGroupService roleGroupService;
    private final RoleAnalyticsService roleAnalyticsService;
    private final AuditMicroserviceClient auditClient;
    private final NotificationClient notificationClient;

    /**
     * Nettoyage automatique des rôles expirés - Tous les jours à 2h du matin
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void cleanupExpiredRoles() {
        log.info("🧹 Début du nettoyage automatique des rôles expirés...");

        try {
            int expiredRoles = userRoleService.cleanupExpiredRoles();
            int expiredGroups = roleGroupService.cleanupExpiredRoleGroups();

            if (expiredRoles > 0 || expiredGroups > 0) {
                // Audit du nettoyage
                auditClient.logAuditEvent(
                        "SCHEDULED_CLEANUP_COMPLETED",
                        "system",
                        String.format("Nettoyage automatique terminé: %d rôles expirés, %d groupes expirés",
                                expiredRoles, expiredGroups),
                        null,
                        0L
                );

                // Notification aux admins
                notificationClient.sendSystemMaintenanceNotification(
                        "Nettoyage automatique des rôles",
                        String.format("Nettoyage terminé avec succès:\n- %d rôles expirés nettoyés\n- %d groupes expirés nettoyés",
                                expiredRoles, expiredGroups),
                        "ROLE_CLEANUP"
                );
            }

            log.info("✅ Nettoyage automatique terminé: {} rôles expirés, {} groupes expirés",
                    expiredRoles, expiredGroups);

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage automatique des rôles expirés", e);

            auditClient.logSecurityEvent(
                    "SCHEDULED_CLEANUP_FAILED",
                    "system",
                    "HIGH",
                    "Échec du nettoyage automatique des rôles: " + e.getMessage(),
                    null
            );

            notificationClient.sendSystemErrorNotification(
                    "Erreur nettoyage automatique des rôles",
                    "Échec du nettoyage automatique: " + e.getMessage(),
                    "SYSTEM_ERROR"
            );
        }
    }

    /**
     * Détection des conflits de rôles - Tous les lundis à 8h
     */
    @Scheduled(cron = "0 0 8 * * MON")
    public void detectRoleConflicts() {
        log.info("🔍 Début de la détection automatique des conflits de rôles...");

        try {
            List<RoleConflictDto> conflicts = roleAnalyticsService.detectRoleConflicts();

            if (!conflicts.isEmpty()) {
                // Audit des conflits détectés
                auditClient.logSecurityEvent(
                        "ROLE_CONFLICTS_DETECTED_SCHEDULED",
                        "system",
                        conflicts.size() > 10 ? "HIGH" : "MEDIUM",
                        String.format("%d conflits de rôles détectés lors de la vérification hebdomadaire",
                                conflicts.size()),
                        null
                );

                // Notification détaillée aux admins
                StringBuilder conflictDetails = new StringBuilder();
                conflictDetails.append(String.format("Détection de %d conflits de rôles:\n\n", conflicts.size()));

                conflicts.stream().limit(5).forEach(conflict -> {
                    conflictDetails.append(String.format("- %s: %s (Sévérité: %s)\n",
                            conflict.getConflictType(), conflict.getDescription(), conflict.getSeverity()));
                });

                if (conflicts.size() > 5) {
                    conflictDetails.append(String.format("\n... et %d autres conflits", conflicts.size() - 5));
                }

                notificationClient.sendSecurityAlertNotification(
                        "Conflits de rôles détectés",
                        conflictDetails.toString(),
                        "ROLE_CONFLICTS",
                        conflicts.size() > 10 ? "HIGH" : "MEDIUM"
                );
            }

            log.info("✅ Détection des conflits terminée: {} conflits détectés", conflicts.size());

        } catch (Exception e) {
            log.error("❌ Erreur lors de la détection des conflits de rôles", e);

            auditClient.logSecurityEvent(
                    "ROLE_CONFLICT_DETECTION_FAILED",
                    "system",
                    "MEDIUM",
                    "Échec de la détection automatique des conflits: " + e.getMessage(),
                    null
            );
        }
    }

    /**
     * Génération de rapport d'utilisation des rôles - Le 1er de chaque mois à 9h
     */
    @Scheduled(cron = "0 0 9 1 * *")
    public void generateMonthlyRoleReport() {
        log.info("📊 Génération du rapport mensuel d'utilisation des rôles...");

        try {
            var analytics = roleAnalyticsService.getRoleAnalytics();
            var conflicts = roleAnalyticsService.detectRoleConflicts();

            // Créer le rapport
            StringBuilder report = new StringBuilder();
            report.append("=== RAPPORT MENSUEL - GESTION DES RÔLES ===\n\n");
            report.append(String.format("Date de génération: %s\n\n", LocalDateTime.now()));

            report.append("📈 STATISTIQUES GÉNÉRALES:\n");
            report.append(String.format("- Total des rôles: %d (Actifs: %d)\n",
                    analytics.getTotalRoles(), analytics.getActiveRoles()));
            report.append(String.format("- Total des permissions: %d (Actives: %d)\n",
                    analytics.getTotalPermissions(), analytics.getActivePermissions()));
            report.append(String.format("- Groupes de rôles: %d (Actifs: %d)\n",
                    analytics.getTotalRoleGroups(), analytics.getActiveRoleGroups()));
            report.append(String.format("- Assignations de rôles: %d (Expirées: %d)\n",
                    analytics.getTotalUserRoleAssignments(), analytics.getExpiredRoleAssignments()));

            report.append("\n🔥 RÔLES LES PLUS UTILISÉS:\n");
            analytics.getMostAssignedRoles().entrySet().stream().limit(5)
                    .forEach(entry -> report.append(String.format("- %s: %d utilisateurs\n",
                            entry.getKey(), entry.getValue())));

            report.append(String.format("\n⚠️ CONFLITS DÉTECTÉS: %d\n", conflicts.size()));
            if (!conflicts.isEmpty()) {
                conflicts.stream().limit(3).forEach(conflict ->
                        report.append(String.format("- %s: %s\n",
                                conflict.getConflictType(), conflict.getDescription())));
            }

            report.append("\n📊 RÉPARTITION PAR CATÉGORIE:\n");
            analytics.getRolesByCategory().forEach((category, count) ->
                    report.append(String.format("- %s: %d rôles\n", category, count)));

            // Audit du rapport
            auditClient.logAuditEvent(
                    "MONTHLY_ROLE_REPORT_GENERATED",
                    "system",
                    String.format("Rapport mensuel généré: %d rôles, %d conflits",
                            analytics.getTotalRoles(), conflicts.size()),
                    null,
                    0L
            );

            // Envoyer le rapport aux admins
            notificationClient.sendMonthlyReportNotification(
                    "Rapport mensuel - Gestion des rôles",
                    report.toString(),
                    "MONTHLY_ROLE_REPORT"
            );

            log.info("✅ Rapport mensuel généré et envoyé");

        } catch (Exception e) {
            log.error("❌ Erreur lors de la génération du rapport mensuel", e);

            auditClient.logSecurityEvent(
                    "MONTHLY_REPORT_GENERATION_FAILED",
                    "system",
                    "MEDIUM",
                    "Échec génération rapport mensuel: " + e.getMessage(),
                    null
            );
        }
    }

    /**
     * Vérification de la santé du système de rôles - Toutes les 6 heures
     */
    @Scheduled(fixedRate = 21600000) // 6 heures en millisecondes
    public void systemHealthCheck() {
        log.debug("🏥 Vérification de la santé du système de rôles...");

        try {
            var analytics = roleAnalyticsService.getRoleAnalytics();
            var conflicts = roleAnalyticsService.detectRoleConflicts();

            // Vérifier des anomalies
            boolean hasIssues = false;
            StringBuilder issues = new StringBuilder();

            // Vérifier les rôles inactifs en masse
            if (analytics.getActiveRoles() * 2 < analytics.getTotalRoles()) {
                hasIssues = true;
                issues.append("- Plus de 50% des rôles sont inactifs\n");
            }

            // Vérifier les assignations expirées en masse
            if (analytics.getExpiredRoleAssignments() > analytics.getTotalUserRoleAssignments() / 4) {
                hasIssues = true;
                issues.append("- Plus de 25% des assignations sont expirées\n");
            }

            // Vérifier les conflits critiques
            long highSeverityConflicts = conflicts.stream()
                    .filter(c -> "HIGH".equals(c.getSeverity()))
                    .count();

            if (highSeverityConflicts > 0) {
                hasIssues = true;
                issues.append(String.format("- %d conflits de haute sévérité détectés\n", highSeverityConflicts));
            }

            if (hasIssues) {
                auditClient.logSecurityEvent(
                        "ROLE_SYSTEM_HEALTH_ISSUES",
                        "system",
                        "MEDIUM",
                        "Problèmes de santé détectés dans le système de rôles:\n" + issues.toString(),
                        null
                );

                log.warn("⚠️ Problèmes de santé détectés dans le système de rôles:\n{}", issues.toString());
            } else {
                log.debug("✅ Système de rôles en bonne santé");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de la vérification de santé du système", e);
        }
    }
}