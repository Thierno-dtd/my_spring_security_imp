package com.example.security.services;

import com.example.security.dto.*;
import com.example.security.entites.User;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailChangeService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final NotificationClient notificationClient;
    private final AuditMicroserviceClient auditMicroserviceClient;

    @Value("${email.change.expiration.hours:24}")
    private int emailChangeExpirationHours;

    @Value("${email.change.max-attempts:3}")
    private int maxEmailChangeAttempts;

    // Regex pour validation email
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$"
    );

    /**
     * Demande de changement d'email
     */
    @Transactional
    public ResponseDto requestEmailChange(EmailChangeRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        String currentUserEmail = SecurityContextHolder.getContext().getAuthentication().getName();

        try {
            User user = userRepository.findByEmail(currentUserEmail)
                    .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));

            // Vérifier le mot de passe actuel
            if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswd())) {
                auditMicroserviceClient.logSecurityEvent(
                        "EMAIL_CHANGE_WRONG_PASSWORD",
                        user.getEmail(),
                        "HIGH",
                        "Tentative changement email avec mauvais mot de passe",
                        httpRequest
                );

                throw new IllegalArgumentException("Mot de passe incorrect");
            }

            // Valider le nouveau email
            if (!isValidEmail(request.getNewEmail())) {
                throw new IllegalArgumentException("Format d'email invalide");
            }

            // Vérifier que ce n'est pas le même email
            if (request.getNewEmail().equalsIgnoreCase(user.getEmail())) {
                throw new IllegalArgumentException("Le nouvel email doit être différent de l'actuel");
            }

            // Vérifier que le nouvel email n'est pas déjà utilisé
            if (userRepository.findByEmail(request.getNewEmail()).isPresent()) {
                auditMicroserviceClient.logSecurityEvent(
                        "EMAIL_CHANGE_DUPLICATE_EMAIL",
                        user.getEmail(),
                        "MEDIUM",
                        "Tentative changement vers email existant: " + request.getNewEmail(),
                        httpRequest
                );

                throw new IllegalArgumentException("Cet email est déjà utilisé par un autre compte");
            }

            // Vérifier s'il y a déjà une demande en cours
            if (user.hasValidEmailChangeToken()) {
                throw new IllegalArgumentException("Une demande de changement d'email est déjà en cours");
            }

            // Générer le token de changement
            String changeToken = generateEmailChangeToken();
            LocalDateTime expiresAt = LocalDateTime.now().plusHours(emailChangeExpirationHours);

            // Sauvegarder la demande
            user.setPendingEmail(request.getNewEmail());
            user.setEmailChangeToken(changeToken);
            user.setEmailChangeExpiresAt(expiresAt);
            userRepository.save(user);

            // Envoyer les emails de confirmation
            sendEmailChangeConfirmationEmails(user, changeToken);

            // Audit
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "EMAIL_CHANGE_REQUESTED",
                    user.getEmail(),
                    "Demande changement email vers: " + request.getNewEmail(),
                    httpRequest,
                    executionTime
            );

            log.info("📧 Demande changement email pour {}: {} -> {}",
                    user.getEmail(), user.getEmail(), request.getNewEmail());

            return ResponseDto.builder()
                    .success(true)
                    .message("Des emails de confirmation ont été envoyés à vos deux adresses. " +
                            "Veuillez confirmer le changement dans les " + emailChangeExpirationHours + " heures.")
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "EMAIL_CHANGE_REQUEST_FAILED",
                    currentUserEmail,
                    "Échec demande changement email: " + e.getMessage(),
                    httpRequest,
                    executionTime
            );

            log.error("❌ Échec demande changement email pour: {}", currentUserEmail, e);
            throw e;
        }

    }

    /**
     * Confirmation du changement d'email
     */
    @Transactional
    public ResponseDto confirmEmailChange(EmailChangeConfirmRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            User user = userRepository.findByEmailChangeToken(request.getToken())
                    .orElseThrow(() -> new IllegalArgumentException("Token de changement d'email invalide"));

            // Vérifier l'expiration
            if (user.getEmailChangeExpiresAt().isBefore(LocalDateTime.now())) {
                auditMicroserviceClient.logSecurityEvent(
                        "EMAIL_CHANGE_EXPIRED_TOKEN",
                        user.getEmail(),
                        "MEDIUM",
                        "Tentative confirmation avec token expiré",
                        httpRequest
                );

                // Nettoyer le token expiré
                user.setPendingEmail(null);
                user.setEmailChangeToken(null);
                user.setEmailChangeExpiresAt(null);
                userRepository.save(user);

                throw new IllegalArgumentException("Le token de changement d'email a expiré");
            }

            // Vérifier une dernière fois que le nouvel email n'est pas pris
            if (userRepository.findByEmail(user.getPendingEmail()).isPresent()) {
                throw new IllegalArgumentException("Le nouvel email est maintenant utilisé par un autre compte");
            }

            String oldEmail = user.getEmail();
            String newEmail = user.getPendingEmail();

            // Effectuer le changement
            user.setEmail(newEmail);
            user.setPendingEmail(null);
            user.setEmailChangeToken(null);
            user.setEmailChangeExpiresAt(null);
            userRepository.save(user);

            // Envoyer les notifications de confirmation
            sendEmailChangeCompleteNotifications(oldEmail, newEmail);

            // Audit critique
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "EMAIL_CHANGED_SUCCESS",
                    newEmail,
                    "Email changé avec succès. Ancien: " + oldEmail,
                    httpRequest,
                    executionTime
            );

            auditMicroserviceClient.logSecurityEvent(
                    "EMAIL_ADDRESS_CHANGED",
                    newEmail,
                    "HIGH",
                    "Changement d'adresse email: " + oldEmail + " -> " + newEmail,
                    httpRequest
            );

            log.info("✅ Email changé avec succès: {} -> {}", oldEmail, newEmail);

            return ResponseDto.builder()
                    .success(true)
                    .message("Votre adresse email a été changée avec succès")
                    .data(newEmail)
                    .build();

        } catch (Exception e) {
            auditMicroserviceClient.logSecurityEvent(
                    "EMAIL_CHANGE_FAILED",
                    "unknown",
                    "HIGH",
                    "Échec changement email: " + e.getMessage(),
                    httpRequest
            );

            log.error("❌ Échec changement email", e);
            throw e;
        }
    }

    /**
     * Obtenir le statut d'une demande de changement d'email
     */
    public EmailChangeStatus getEmailChangeStatus() {
        String currentUserEmail = SecurityContextHolder.getContext().getAuthentication().getName();

        try {
            User user = userRepository.findByEmail(currentUserEmail)
                    .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));

            if (!user.hasValidEmailChangeToken()) {
                return EmailChangeStatus.builder()
                        .hasPendingChange(false)
                        .build();
            }

            long hoursRemaining = java.time.Duration.between(
                    LocalDateTime.now(),
                    user.getEmailChangeExpiresAt()
            ).toHours();

            return EmailChangeStatus.builder()
                    .hasPendingChange(true)
                    .pendingEmail(user.getPendingEmail())
                    .expiresAt(user.getEmailChangeExpiresAt())
                    .hoursRemaining(Math.max(0, hoursRemaining))
                    .build();

        } catch (Exception e) {
            log.error("❌ Erreur récupération statut changement email pour: {}", currentUserEmail, e);
            return EmailChangeStatus.builder().hasPendingChange(false).build();
        }
    }

    /**
     * Annuler une demande de changement d'email en cours
     */
    @Transactional
    public ResponseDto cancelEmailChange() {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        String currentUserEmail = SecurityContextHolder.getContext().getAuthentication().getName();

        try {
            User user = userRepository.findByEmail(currentUserEmail)
                    .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));

            if (!user.hasValidEmailChangeToken()) {
                return ResponseDto.builder()
                        .success(false)
                        .message("Aucune demande de changement d'email en cours")
                        .build();
            }

            String pendingEmail = user.getPendingEmail();

            // Nettoyer la demande
            user.setPendingEmail(null);
            user.setEmailChangeToken(null);
            user.setEmailChangeExpiresAt(null);
            userRepository.save(user);

            // Audit
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "EMAIL_CHANGE_CANCELLED",
                    user.getEmail(),
                    "Annulation demande de changement vers: " + pendingEmail,
                    httpRequest,
                    executionTime
            );

            auditMicroserviceClient.logSecurityEvent(
                    "EMAIL_CHANGE_CANCELLED",
                    user.getEmail(),
                    "LOW",
                    "Demande de changement d'email annulée",
                    httpRequest
            );

            log.info("❎ Demande de changement d'email annulée pour {} (vers: {})",
                    user.getEmail(), pendingEmail);

            return ResponseDto.builder()
                    .success(true)
                    .message("Votre demande de changement d'email a été annulée avec succès")
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "EMAIL_CHANGE_CANCEL_FAILED",
                    currentUserEmail,
                    "Échec annulation demande changement email: " + e.getMessage(),
                    httpRequest,
                    executionTime
            );

            log.error("❌ Erreur lors de l'annulation de la demande de changement email pour {}",
                    currentUserEmail, e);
            throw e;
        }
    }

    /**
     * Validation avancée d'email
     */
    public EmailValidationResult validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return EmailValidationResult.builder()
                    .valid(false)
                    .reason("Email vide")
                    .build();
        }

        email = email.trim().toLowerCase();

        // Vérifications techniques
        if (email.length() > 254) {
            return EmailValidationResult.builder()
                    .valid(false)
                    .reason("Email trop long (max 254 caractères)")
                    .build();
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return EmailValidationResult.builder()
                    .valid(false)
                    .reason("Format d'email invalide")
                    .build();
        }

        // Vérifier les domaines suspects ou jetables
        if (isDisposableEmailDomain(email)) {
            return EmailValidationResult.builder()
                    .valid(false)
                    .reason("Les emails jetables ne sont pas autorisés")
                    .build();
        }

        // Vérifier si déjà utilisé
        if (userRepository.findByEmail(email).isPresent()) {
            return EmailValidationResult.builder()
                    .valid(false)
                    .reason("Cet email est déjà utilisé")
                    .build();
        }

        return EmailValidationResult.builder()
                .valid(true)
                .reason("Email valide")
                .build();
    }

    private boolean isDisposableEmailDomain(String email) {
        // Liste des domaines d'emails jetables courants
        String[] disposableDomains = {
                "10minutemail.com", "guerrillamail.com", "mailinator.com",
                "yopmail.com", "tempmail.org", "trash-mail.com"
        };

        String domain = email.substring(email.lastIndexOf("@") + 1).toLowerCase();

        for (String disposable : disposableDomains) {
            if (domain.equals(disposable) || domain.endsWith("." + disposable)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Nettoyage automatique des tokens expirés
     */
    @Scheduled(fixedRate = 3600000) // 1 heure
    @Transactional
    public void cleanupExpiredEmailChangeTokens() {
        try {
            LocalDateTime now = LocalDateTime.now();
            List<User> expiredUsers = userRepository.findAll().stream()
                    .filter(user -> user.getEmailChangeExpiresAt() != null &&
                            user.getEmailChangeExpiresAt().isBefore(now))
                    .toList();

            for (User user : expiredUsers) {
                String pendingEmail = user.getPendingEmail();

                user.setPendingEmail(null);
                user.setEmailChangeToken(null);
                user.setEmailChangeExpiresAt(null);
                userRepository.save(user);

                auditMicroserviceClient.logAuditEvent(
                        "EMAIL_CHANGE_TOKEN_EXPIRED",
                        user.getEmail(),
                        "Token changement email expiré (vers: " + pendingEmail + ")",
                        null,
                        0L
                );
            }

            if (!expiredUsers.isEmpty()) {
                log.info("🧹 {} tokens de changement email expirés nettoyés", expiredUsers.size());
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage des tokens de changement email", e);
        }
    }

    // Méthodes privées utilitaires
    private boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }

        email = email.trim().toLowerCase();

        // Vérifications de base
        if (email.length() > 254) return false;
        if (email.startsWith(".") || email.endsWith(".")) return false;
        if (email.contains("..")) return false;

        return EMAIL_PATTERN.matcher(email).matches();
    }

    private String generateEmailChangeToken() {
        return UUID.randomUUID().toString() + "-" + System.currentTimeMillis();
    }

    private void sendEmailChangeConfirmationEmails(User user, String token) {
        try {
            // Email à l'ancienne adresse
            log.info("📧 Envoi confirmation changement à l'ancienne adresse: {}", user.getEmail());
            notificationClient.sendEmailChangeRequestToOldEmail(user.getEmail(), user.getName(), user.getPendingEmail());

            // Email à la nouvelle adresse avec token de confirmation
            log.info("📧 Envoi lien confirmation à la nouvelle adresse: {}", user.getPendingEmail());
            notificationClient.sendEmailChangeConfirmationToNewEmail(user.getPendingEmail(), user.getName(), token);

        } catch (Exception e) {
            log.error("❌ Erreur envoi emails changement pour: {}", user.getEmail(), e);
        }
    }

    private void sendEmailChangeCompleteNotifications(String oldEmail, String newEmail) {
        try {
            // Notification à l'ancienne adresse
            log.info("📧 Notification changement terminé à l'ancienne adresse: {}", oldEmail);

            // Notification à la nouvelle adresse
            log.info("📧 Notification changement terminé à la nouvelle adresse: {}", newEmail);

             notificationClient.sendEmailChangeCompleteNotifications(oldEmail, newEmail);

        } catch (Exception e) {
            log.error("❌ Erreur envoi notifications fin changement: {} -> {}", oldEmail, newEmail, e);
        }
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }

}

