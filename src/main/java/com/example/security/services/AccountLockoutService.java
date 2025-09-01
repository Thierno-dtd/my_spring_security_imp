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
            // Incrémenter le compteur d'échecs
            user.incrementFailedLoginAttempts();

            // Calculer la durée de verrouillage (progressive ou fixe)
            int lockoutDuration = calculateLockoutDuration(user.getFailedLoginAttempts());

            // Verrouiller si nécessaire
            if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
                user.lockTemporarily(lockoutDuration);
                userRepository.save(user);

                // Notification de sécurité
                sendAccountLockedNotification(user, lockoutDuration);

                // Audit critique
                auditMicroserviceClient.logSecurityEvent(
                        "ACCOUNT_LOCKED_FAILED_ATTEMPTS",
                        user.getEmail(),
                        "HIGH",
                        "Compte verrouillé après " + user.getFailedLoginAttempts() + " tentatives échouées",
                        request
                );

                log.warn("🔒 Compte verrouillé pour {} tentatives: {} (durée: {}min)",
                        user.getEmail(), user.getFailedLoginAttempts(), lockoutDuration);

            } else {
                userRepository.save(user);

                // Avertissement avant verrouillage
                int remainingAttempts = maxFailedAttempts - user.getFailedLoginAttempts();
                auditMicroserviceClient.logSecurityEvent(
                        "MULTIPLE_FAILED_LOGIN_ATTEMPTS",
                        user.getEmail(),
                        "MEDIUM",
                        "Tentatives échouées: " + user.getFailedLoginAttempts() +
                                " (reste " + remainingAttempts + " avant verrouillage)",
                        request
                );

                log.warn("⚠️ Tentatives échouées pour {}: {} (reste {})",
                        user.getEmail(), user.getFailedLoginAttempts(), remainingAttempts);
            }
        }

        // Vérifier les tentatives par IP
        checkIpBasedLockout(ipAddress, request);
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
            return false;
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        // Audit
        auditMicroserviceClient.logAuditEvent(
                "ACCOUNT_UNLOCKED_MANUALLY",
                user.getEmail(),
                "Compte déverrouillé manuellement par " + adminEmail + ". Raison: " + reason,
                null,
                0L
        );

        // Notification à l'utilisateur
        sendAccountUnlockedNotification(user, adminEmail);

        log.info("🔓 Compte déverrouillé manuellement: {} par {}", email, adminEmail);
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
                user.setLockedUntil(null);
                userRepository.save(user);

                auditMicroserviceClient.logAuditEvent(
                        "ACCOUNT_UNLOCKED_AUTOMATICALLY",
                        user.getEmail(),
                        "Déverrouillage automatique après expiration",
                        null,
                        0L
                );
            }

            if (!usersToUnlock.isEmpty()) {
                log.info("🔓 {} comptes déverrouillés automatiquement", usersToUnlock.size());
            }

        } catch (Exception e) {
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
            // TODO: Implémenter via NotificationClient
            // notificationClient.sendAccountLockedNotification(user.getEmail(), user.getName(), lockoutDuration);
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

}