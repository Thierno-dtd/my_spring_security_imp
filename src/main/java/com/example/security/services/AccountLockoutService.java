package com.example.security.services;

import com.example.security.dto.LockoutInfo;
import com.example.security.dto.SecurityStats;
import com.example.security.entites.LoginAttempt;
import com.example.security.entites.User;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.repositories.LoginAttemptRepository;
import com.example.security.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountLockoutService {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final AuditMicroserviceClient auditMicroserviceClient;
    private final NotificationClient notificationClient;

    @Value("${security.lockout.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.lockout.window-minutes:15}")
    private int lockoutWindowMinutes;

    @Value("${security.lockout.duration-minutes:30}")
    private int lockoutDurationMinutes;

    @Value("${security.lockout.ip-max-attempts:10}")
    private int maxIpAttempts;

    @Value("${security.lockout.progressive-enabled:true}")
    private boolean progressiveLockoutEnabled;

    /**
     * Enregistre une tentative de connexion
     */
    public void recordLoginAttempt(String email, String ipAddress, boolean success,
                                   String failureReason, HttpServletRequest request) {
        try {
            LoginAttempt attempt = LoginAttempt.builder()
                    .email(email)
                    .ipAddress(ipAddress)
                    .success(success)
                    .failureReason(failureReason)
                    .userAgent(request.getHeader("User-Agent"))
                    .build();

            loginAttemptRepository.save(attempt);

            if (!success) {
                handleFailedLogin(email, ipAddress, request);
            } else {
                handleSuccessfulLogin(email);
            }

        } catch (Exception e) {
            log.error("❌ Erreur enregistrement tentative connexion pour {}: {}", email, e.getMessage());
        }
    }

    /**
     * Traite une connexion échouée
     */
    @Transactional
    protected void handleFailedLogin(String email, String ipAddress, HttpServletRequest request) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user != null) {
            int previousFailedAttempts = user.getFailedLoginAttempts() != null ? user.getFailedLoginAttempts() : 0;
            user.incrementFailedLoginAttempts();
            int currentFailedAttempts = user.getFailedLoginAttempts();

            // AUDIT: Chaque tentative échouée
            auditMicroserviceClient.logSecurityEvent(
                    "FAILED_LOGIN_ATTEMPT",
                    user.getEmail(),
                    "MEDIUM",
                    String.format("Tentative %d/%d depuis IP: %s", currentFailedAttempts, maxFailedAttempts, ipAddress),
                    request
            );

            // Calculer la durée de verrouillage (progressive ou fixe)
            int lockoutDuration = calculateLockoutDuration(currentFailedAttempts);

            // Verrouiller si nécessaire
            if (currentFailedAttempts >= maxFailedAttempts) {
                LocalDateTime previousLockUntil = user.getLockedUntil();
                user.lockTemporarily(lockoutDuration);
                userRepository.save(user);

                // AUDIT: Verrouillage avec détails de progression
                auditMicroserviceClient.logSecurityEvent(
                        "ACCOUNT_LOCKED_FAILED_ATTEMPTS",
                        user.getEmail(),
                        "HIGH",
                        String.format("Compte verrouillé après %d tentatives. Durée: %d min. IP: %s. Progression: %s",
                                currentFailedAttempts, lockoutDuration, ipAddress,
                                progressiveLockoutEnabled ? "progressive" : "fixe"),
                        request
                );

                // AUDIT: Si c'est un re-verrouillage
                if (previousLockUntil != null && previousLockUntil.isAfter(LocalDateTime.now())) {
                    auditMicroserviceClient.logSecurityEvent(
                            "ACCOUNT_RE_LOCKED",
                            user.getEmail(),
                            "CRITICAL",
                            "Compte reverrouillé alors qu'il était déjà verrouillé jusqu'à: " + previousLockUntil,
                            request
                    );
                }

                // Notification de sécurité
                sendAccountLockedNotification(user, lockoutDuration);
                log.warn("🔒 Compte verrouillé pour {} tentatives: {} (durée: {}min)",
                        user.getEmail(), currentFailedAttempts, lockoutDuration);

            } else {
                userRepository.save(user);

                int remainingAttempts = maxFailedAttempts - currentFailedAttempts;

                // AUDIT: Progression vers verrouillage
                auditMicroserviceClient.logSecurityEvent(
                        "ACCOUNT_LOCKOUT_WARNING",
                        user.getEmail(),
                        "MEDIUM",
                        String.format("Tentatives échouées: %d/%d. Reste %d avant verrouillage. IP: %s",
                                currentFailedAttempts, maxFailedAttempts, remainingAttempts, ipAddress),
                        request
                );

                // Envoyer alerte si seuil critique atteint
                if (currentFailedAttempts >= 3) {
                    sendSecurityAlert(email, currentFailedAttempts, remainingAttempts);
                }

                log.warn("⚠️ Tentatives échouées pour {}: {} (reste {})",
                        user.getEmail(), currentFailedAttempts, remainingAttempts);
            }
        }

        // Vérifier les tentatives par IP avec audit détaillé
        checkIpBasedLockoutWithAudit(ipAddress, request);
    }


    /**
     * Traite une connexion réussie
     */
    @Transactional
    protected void handleSuccessfulLogin(String email) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user != null && user.getFailedLoginAttempts() > 0) {
            user.resetFailedLoginAttempts();
            userRepository.save(user);

            log.info("✅ Compteur d'échecs réinitialisé pour: {}", email);
        }
    }

    /**
     * Vérifie si un utilisateur est temporairement verrouillé
     */
    public boolean isAccountLocked(String email) {
        return userRepository.findByEmail(email)
                .map(User::isTemporarilyLocked)
                .orElse(false);
    }

    /**
     * Obtient les informations de verrouillage
     */
    public LockoutInfo getLockoutInfo(String email) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            return LockoutInfo.builder()
                    .locked(false)
                    .build();
        }

        boolean isLocked = user.isTemporarilyLocked();
        int failedAttempts = user.getFailedLoginAttempts() != null ? user.getFailedLoginAttempts() : 0;
        int remainingAttempts = Math.max(0, maxFailedAttempts - failedAttempts);

        return LockoutInfo.builder()
                .locked(isLocked)
                .failedAttempts(failedAttempts)
                .remainingAttempts(remainingAttempts)
                .lockedUntil(user.getLockedUntil())
                .minutesRemaining(isLocked ? calculateMinutesRemaining(user.getLockedUntil()) : 0)
                .build();
    }

    /**
     * Déverrouillage manuel d'un compte (admin)
     */
    @Transactional
    public boolean unlockAccount(String email, String adminEmail, String reason) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            // AUDIT: Tentative de déverrouillage d'un compte inexistant
            auditMicroserviceClient.logSecurityEvent(
                    "UNLOCK_ATTEMPT_UNKNOWN_USER",
                    adminEmail,
                    "MEDIUM",
                    "Tentative de déverrouillage d'un compte inexistant: " + email,
                    null
            );
            return false;
        }

        // AUDIT: État avant déverrouillage
        boolean wasLocked = user.isTemporarilyLocked();
        int failedAttemptsBeforeReset = user.getFailedLoginAttempts() != null ? user.getFailedLoginAttempts() : 0;
        LocalDateTime lockUntilBefore = user.getLockedUntil();

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        // AUDIT: Déverrouillage avec détails complets
        auditMicroserviceClient.logAuditEvent(
                "ACCOUNT_UNLOCKED_MANUALLY",
                user.getEmail(),
                String.format("Déverrouillage manuel par %s. État précédent: locked=%s, attempts=%d, lockedUntil=%s. Raison: %s",
                        adminEmail, wasLocked, failedAttemptsBeforeReset, lockUntilBefore, reason),
                null,
                0L
        );

        // AUDIT: Sécurité critique pour actions admin
        auditMicroserviceClient.logSecurityEvent(
                "ADMIN_ACCOUNT_UNLOCK",
                adminEmail,
                "HIGH",
                String.format("Déverrouillage administrateur du compte %s. Raison: %s", user.getEmail(), reason),
                null
        );

        // Notification à l'utilisateur
        sendAccountUnlockedNotification(user, adminEmail);

        log.info("🔓 Compte déverrouillé manuellement: {} par {} (était locked: {}, attempts: {})",
                email, adminEmail, wasLocked, failedAttemptsBeforeReset);
        return true;
    }

    /**
     * Nettoyage automatique des verrouillages expirés
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    @Transactional
    public void cleanupExpiredLockouts() {
        try {
            LocalDateTime now = LocalDateTime.now();
            List<User> usersToUnlock = userRepository.findUsersToUnlock(now);

            for (User user : usersToUnlock) {
                LocalDateTime wasLockedUntil = user.getLockedUntil();
                user.setLockedUntil(null);
                userRepository.save(user);

                // AUDIT: Chaque déverrouillage automatique avec durée
                long lockDurationMinutes = java.time.Duration.between(user.getLastLoginAttempt(), now).toMinutes();
                auditMicroserviceClient.logAuditEvent(
                        "ACCOUNT_UNLOCKED_AUTOMATICALLY",
                        user.getEmail(),
                        String.format("Déverrouillage automatique après %d minutes (était locked jusqu'à: %s)",
                                lockDurationMinutes, wasLockedUntil),
                        null,
                        0L
                );
            }

            if (!usersToUnlock.isEmpty()) {
                // AUDIT: Statistiques de nettoyage
                auditMicroserviceClient.logAuditEvent(
                        "LOCKOUT_CLEANUP_COMPLETED",
                        "system",
                        String.format("Nettoyage terminé: %d comptes déverrouillés automatiquement", usersToUnlock.size()),
                        null,
                        0L
                );

                log.info("🔓 {} comptes déverrouillés automatiquement", usersToUnlock.size());
            }

        } catch (Exception e) {
            // AUDIT: Erreurs de nettoyage
            auditMicroserviceClient.logSecurityEvent(
                    "LOCKOUT_CLEANUP_ERROR",
                    "system",
                    "MEDIUM",
                    "Erreur lors du nettoyage des verrouillages: " + e.getMessage(),
                    null
            );
            log.error("❌ Erreur lors du nettoyage des verrouillages expirés", e);
        }
    }

    /**
     * Nettoyage des anciennes tentatives de connexion
     */
    @Scheduled(cron = "0 0 2 * * ?") // Tous les jours à 2h
    @Transactional
    public void cleanupOldLoginAttempts() {
        try {
            LocalDateTime cutoffDate = LocalDateTime.now().minusDays(30);
            int deleted = loginAttemptRepository.cleanupOldLoginAttempts(cutoffDate);

            if (deleted > 0) {
                log.info("🧹 {} anciennes tentatives de connexion supprimées", deleted);
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage des tentatives de connexion", e);
        }
    }

    /**
     * Détection d'activité suspecte par IP
     */
    private void checkIpBasedLockout(String ipAddress, HttpServletRequest request) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(lockoutWindowMinutes);
        long recentFailures = loginAttemptRepository.countFailedAttemptsByIpSince(ipAddress, since);

        if (recentFailures >= maxIpAttempts) {
            auditMicroserviceClient.logSecurityEvent(
                    "SUSPICIOUS_IP_ACTIVITY",
                    "system",
                    "HIGH",
                    "IP suspecte: " + ipAddress + " (" + recentFailures + " échecs en " +
                            lockoutWindowMinutes + " minutes)",
                    request
            );

            log.warn("🚨 Activité suspecte détectée pour IP: {} ({} échecs)", ipAddress, recentFailures);
        }
    }

    /**
     * Calcule la durée de verrouillage (progressive si activée)
     */
    private int calculateLockoutDuration(int failedAttempts) {
        if (!progressiveLockoutEnabled) {
            return lockoutDurationMinutes;
        }

        // Verrouillage progressif : durée augmente avec les tentatives
        int baseDuration = lockoutDurationMinutes;
        int multiplier = Math.min(failedAttempts - maxFailedAttempts + 1, 5); // Max 5x

        return baseDuration * multiplier;
    }

    private int calculateMinutesRemaining(LocalDateTime lockedUntil) {
        if (lockedUntil == null) return 0;
        return (int) java.time.Duration.between(LocalDateTime.now(), lockedUntil).toMinutes();
    }

    private void sendAccountLockedNotification(User user, int lockoutDuration) {
        try {
            log.info("📧 Envoi notification verrouillage à: {} (durée: {}min)", user.getEmail(), lockoutDuration);

            notificationClient.sendAccountLockedNotification(user.getEmail(), user.getName(), lockoutDuration);
        } catch (Exception e) {
            log.error("❌ Erreur envoi notification verrouillage pour: {}", user.getEmail(), e);
        }
    }

    private void sendAccountUnlockedNotification(User user, String adminEmail) {
        try {
            log.info("📧 Envoi notification déverrouillage à: {}", user.getEmail());
            // TODO: Implémenter via NotificationClient
        } catch (Exception e) {
            log.error("❌ Erreur envoi notification déverrouillage pour: {}", user.getEmail(), e);
        }
    }


    /**
     * Notification d'activité suspecte par IP (nouvelle méthode)
     */
    public void sendSuspiciousActivityNotification(String ipAddress, long failureCount, String userEmail) {
        try {
            if (userEmail != null) {
                User user = userRepository.findByEmail(userEmail).orElse(null);
                if (user != null) {
                    log.info("📧 Envoi notification activité suspecte à: {}", userEmail);

                    // Utiliser un template générique de sécurité ou créer un template spécifique
                    Map<String, String> parameters = Map.of(
                            "ipAddress", ipAddress,
                            "failureCount", String.valueOf(failureCount),
                            "detectionTime", LocalDateTime.now().toString()
                    );

                    notificationClient.sendSuspiciousActivityNotification(user.getEmail(), user.getName(), parameters);
                }
            }
        } catch (Exception e) {
            log.error("❌ Erreur envoi notification activité suspecte pour IP: {}", ipAddress, e);
        }
    }

    /**
     * Alerte de sécurité pour tentatives multiples (nouvelle méthode)
     */
    public void sendSecurityAlert(String email, int failedAttempts, int remainingAttempts) {
        try {
            if (failedAttempts >= 3) { // Seuil d'alerte
                User user = userRepository.findByEmail(email).orElse(null);
                if (user != null) {
                    log.info("📧 Envoi alerte sécurité à: {} ({} tentatives)", email, failedAttempts);

                    // Template pour alerte avant verrouillage
                    Map<String, String> parameters = Map.of(
                            "failedAttempts", String.valueOf(failedAttempts),
                            "remainingAttempts", String.valueOf(remainingAttempts),
                            "maxAttempts", String.valueOf(maxFailedAttempts)
                    );

                    notificationClient.sendSecurityWarning(user.getEmail(), user.getName(), parameters);
                }
            }
        } catch (Exception e) {
            log.error("❌ Erreur envoi alerte sécurité pour: {}", email, e);
        }
    }

    /**
     * Rapport quotidien de sécurité (nouvelle méthode)
     */
    @Scheduled(cron = "0 0 8 * * ?") // Tous les jours à 8h
    public void sendDailySecurityReport() {
        try {
            LocalDateTime yesterday = LocalDateTime.now().minusDays(1);

            // Statistiques du jour précédent
            long lockedAccounts = userRepository.countLockedAccountsSince(yesterday);
            long failedAttempts = loginAttemptRepository.countFailedAttemptsSince(yesterday);
            long suspiciousIPs = getSuspiciousIpCountSince(yesterday);

            if (lockedAccounts > 0 || failedAttempts > 10) {
                log.info("📊 Envoi rapport quotidien de sécurité");

                Map<String, String> stats = Map.of(
                        "date", yesterday.toLocalDate().toString(),
                        "lockedAccounts", String.valueOf(lockedAccounts),
                        "failedAttempts", String.valueOf(failedAttempts),
                        "suspiciousIPs", String.valueOf(suspiciousIPs)
                );

                notificationClient.sendSecurityReport("admin@example.com", stats);
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi du rapport quotidien", e);
        }
    }

    private long getSuspiciousIpCountSince(LocalDateTime since) {
        List<Object[]> suspiciousIps = loginAttemptRepository.findSuspiciousIpAddresses(since, maxIpAttempts);
        return suspiciousIps.size();
    }

    /**
     * Méthode pour envoyer des notifications d'expiration de verrouillage
     */
    @Scheduled(fixedRate = 300000) // 5 minutes - à ajouter au nettoyage existant
    public void notifyUpcomingUnlocks() {
        try {
            LocalDateTime in5Minutes = LocalDateTime.now().plusMinutes(5);
            LocalDateTime in15Minutes = LocalDateTime.now().plusMinutes(15);

            // Trouver les comptes qui seront déverrouillés bientôt
            List<User> soonToBeUnlocked = userRepository.findUsersUnlockingSoon(in5Minutes, in15Minutes);

            for (User user : soonToBeUnlocked) {
                int minutesRemaining = calculateMinutesRemaining(user.getLockedUntil());

                if (minutesRemaining <= 5 && minutesRemaining > 0) {
                    log.info("📧 Notification de déverrouillage imminent pour: {}", user.getEmail());

                    Map<String, String> parameters = Map.of(
                            "minutesRemaining", String.valueOf(minutesRemaining)
                    );

                    notificationClient.sendUnlockSoonNotification(user.getEmail(), user.getName(), parameters);
                }
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors des notifications de déverrouillage imminent", e);
        }
    }

/**
     * Statistiques de sécurité
     */
    public SecurityStats getSecurityStats() {
        LocalDateTime last24h = LocalDateTime.now().minusDays(1);

        return SecurityStats.builder()
                .currentlyLockedAccounts(userRepository.countByAccountStatus(
                        com.example.security.constants.AccountStatus.LOCKED))
                .totalLoginAttempts(loginAttemptRepository.count())
                .suspiciousIpCount(getSuspiciousIpCount())
                .build();
    }

    private long getSuspiciousIpCount() {
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        List<Object[]> suspiciousIps = loginAttemptRepository.findSuspiciousIpAddresses(since, maxIpAttempts);
        return suspiciousIps.size();
    }

    private void checkIpBasedLockoutWithAudit(String ipAddress, HttpServletRequest request) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(lockoutWindowMinutes);
        long recentFailures = loginAttemptRepository.countFailedAttemptsByIpSince(ipAddress, since);

        // AUDIT: Suivi des tentatives par IP
        if (recentFailures > 0) {
            auditMicroserviceClient.logAuditEvent(
                    "IP_LOGIN_ATTEMPTS_TRACKED",
                    "system",
                    String.format("IP %s: %d tentatives en %d minutes", ipAddress, recentFailures, lockoutWindowMinutes),
                    request,
                    0L
            );
        }

        // Seuils d'alerte progressifs
        if (recentFailures >= maxIpAttempts) {
            auditMicroserviceClient.logSecurityEvent(
                    "SUSPICIOUS_IP_ACTIVITY_CRITICAL",
                    "system",
                    "CRITICAL",
                    String.format("IP suspecte CRITIQUE: %s (%d échecs en %d minutes)",
                            ipAddress, recentFailures, lockoutWindowMinutes),
                    request
            );

            // Récupérer les emails concernés pour notification
            List<String> affectedEmails = getEmailsFromIpAttempts(ipAddress, since);
            for (String email : affectedEmails) {
                sendSuspiciousActivityNotification(ipAddress, recentFailures, email);
            }

            log.error("🚨 CRITIQUE: Activité suspecte IP: {} ({} échecs)", ipAddress, recentFailures);

        } else if (recentFailures >= (maxIpAttempts * 0.7)) { // 70% du seuil
            auditMicroserviceClient.logSecurityEvent(
                    "SUSPICIOUS_IP_ACTIVITY_HIGH",
                    "system",
                    "HIGH",
                    String.format("IP suspecte ÉLEVÉE: %s (%d échecs en %d minutes, seuil à %d)",
                            ipAddress, recentFailures, lockoutWindowMinutes, maxIpAttempts),
                    request
            );

            log.warn("⚠️ ÉLEVÉ: Activité suspecte IP: {} ({} échecs)", ipAddress, recentFailures);

        } else if (recentFailures >= (maxIpAttempts * 0.4)) { // 40% du seuil
            auditMicroserviceClient.logSecurityEvent(
                    "SUSPICIOUS_IP_ACTIVITY_MEDIUM",
                    "system",
                    "MEDIUM",
                    String.format("IP suspecte MODÉRÉE: %s (%d échecs en %d minutes)",
                            ipAddress, recentFailures, lockoutWindowMinutes),
                    request
            );
        }
    }

    private List<String> getEmailsFromIpAttempts(String ipAddress, LocalDateTime since) {
        // Cette méthode nécessiterait une requête dans LoginAttemptRepository
        // public List<String> findDistinctEmailsByIpAndSince(String ipAddress, LocalDateTime since);
        return loginAttemptRepository.findDistinctEmailsByIpAndSince(ipAddress, since);
    }
}