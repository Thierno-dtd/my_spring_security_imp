package com.example.security.services;

import com.example.security.entites.User;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.repositories.UserRepository;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountCleanupService {

    private final UserRepository userRepository;
    private final AuditMicroserviceClient auditMicroserviceClient;

    @Value("${cleanup.unverified.accounts.days:7}")
    private int cleanupDays;

    /**
     * Nettoie les comptes non vérifiés après X jours
     * Exécuté tous les jours à 2h00 du matin
     */
    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void cleanupExpiredUnverifiedAccounts() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(cleanupDays);

        try {
            // Récupérer les comptes à supprimer pour audit
            List<User> usersToDelete = userRepository.findAll().stream()
                    .filter(user -> user.getCreatedAt().isBefore(cutoffDate) && !user.getEmailVerified())
                    .collect(Collectors.toList());

            // Supprimer les comptes
            int deletedCount = userRepository.cleanupUnverifiedAccountsOlderThan(cutoffDate);

            // Audit pour chaque compte supprimé
            usersToDelete.forEach(user -> {
                auditMicroserviceClient.logAuditEvent(
                        "ACCOUNT_CLEANUP_UNVERIFIED",
                        user.getEmail(),
                        "Compte non vérifié supprimé après " + cleanupDays + " jours",
                        null,
                        0L
                );
            });

            log.info("🧹 Nettoyage terminé : {} comptes non vérifiés supprimés", deletedCount);

            // Log général
            if (deletedCount > 0) {
                auditMicroserviceClient.logAuditEvent(
                        "BULK_ACCOUNT_CLEANUP",
                        "system",
                        "Suppression de " + deletedCount + " comptes non vérifiés",
                        null,
                        0L
                );
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage des comptes non vérifiés", e);

            auditMicroserviceClient.logSecurityEvent(
                    "ACCOUNT_CLEANUP_FAILED",
                    "system",
                    "MEDIUM",
                    "Échec du nettoyage automatique : " + e.getMessage(),
                    null
            );
        }
    }

    /**
     * Nettoie les tokens de vérification expirés
     * Exécuté toutes les heures
     */
    @Scheduled(fixedRate = 3600000) // 1 heure
    @Transactional
    public void cleanupExpiredVerificationTokens() {
        LocalDateTime now = LocalDateTime.now();

        try {
            List<User> expiredUsers = userRepository.findExpiredUnverifiedUsers(now);

            for (User user : expiredUsers) {
                user.setEmailVerificationToken(null);
                user.setEmailVerificationExpiresAt(null);
                userRepository.save(user);
            }

            if (!expiredUsers.isEmpty()) {
                log.info("🗑️ {} tokens de vérification expirés nettoyés", expiredUsers.size());
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage des tokens expirés", e);
        }
    }

    /**
     * Méthode manuelle pour forcer le nettoyage
     */
    public CleanupResult forceCleanup(int daysOld) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysOld);

        // Compter avant suppression
        List<User> usersToDelete = userRepository.findAll().stream()
                .filter(user -> user.getCreatedAt().isBefore(cutoffDate) && !user.getEmailVerified())
                .collect(Collectors.toList());

        int deletedCount = userRepository.cleanupUnverifiedAccountsOlderThan(cutoffDate);

        // Audit
        auditMicroserviceClient.logAuditEvent(
                "MANUAL_ACCOUNT_CLEANUP",
                "admin",
                "Nettoyage manuel : " + deletedCount + " comptes supprimés (+" + daysOld + " jours)",
                null,
                0L
        );

        return CleanupResult.builder()
                .deletedCount(deletedCount)
                .cutoffDate(cutoffDate)
                .emails(usersToDelete.stream().map(User::getEmail).collect(Collectors.toList()))
                .build();
    }

    @Data
    @Builder
    public static class CleanupResult {
        private int deletedCount;
        private LocalDateTime cutoffDate;
        private List<String> emails;
    }
}