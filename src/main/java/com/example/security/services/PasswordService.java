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
public class PasswordService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final NotificationClient notificationClient;
    private final AuditMicroserviceClient auditMicroserviceClient;

    @Value("${password.reset.expiration.hours:2}")
    private int passwordResetExpirationHours;

    @Value("${password.reset.max-attempts:5}")
    private int maxPasswordResetAttempts;

    // Regex pour validation mot de passe fort
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    );

    /**
     * Demande de réinitialisation de mot de passe
     */
    public ResponseDto requestPasswordReset(PasswordResetRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new IllegalArgumentException("Aucun compte trouvé avec cet email"));

            // Vérifier si c'est un compte Google (pas de mot de passe)
            if (user.isGoogleUser() && (user.getPasswd() == null || user.getPasswd().isEmpty())) {
                auditMicroserviceClient.logSecurityEvent(
                        "PASSWORD_RESET_ATTEMPT_GOOGLE_ACCOUNT",
                        user.getEmail(),
                        "MEDIUM",
                        "Tentative de reset mot de passe sur compte Google",
                        httpRequest
                );

                throw new IllegalArgumentException("Ce compte utilise Google. Connectez-vous avec Google.");
            }

            // Vérifier le nombre de tentatives
            if (user.getPasswordResetAttempts() != null &&
                    user.getPasswordResetAttempts() >= maxPasswordResetAttempts) {

                auditMicroserviceClient.logSecurityEvent(
                        "PASSWORD_RESET_MAX_ATTEMPTS",
                        user.getEmail(),
                        "HIGH",
                        "Trop de tentatives de réinitialisation mot de passe",
                        httpRequest
                );

                throw new IllegalArgumentException("Trop de tentatives. Contactez le support.");
            }

            // Générer le token de reset
            String resetToken = generatePasswordResetToken();
            LocalDateTime expiresAt = LocalDateTime.now().plusHours(passwordResetExpirationHours);

            // Sauvegarder le token
            user.setPasswordResetToken(resetToken);
            user.setPasswordResetExpiresAt(expiresAt);
            user.incrementPasswordResetAttempts();
            userRepository.save(user);

            // Envoyer l'email de réinitialisation
            sendPasswordResetEmail(user, resetToken);

            // Audit
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "PASSWORD_RESET_REQUESTED",
                    user.getEmail(),
                    "Demande de réinitialisation mot de passe",
                    httpRequest,
                    executionTime
            );

            log.info("📧 Demande de réinitialisation mot de passe pour: {}", user.getEmail());

            return ResponseDto.builder()
                    .success(true)
                    .message("Un email de réinitialisation a été envoyé à votre adresse")
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "PASSWORD_RESET_REQUEST_FAILED",
                    request.getEmail(),
                    "Échec demande reset: " + e.getMessage(),
                    httpRequest,
                    executionTime
            );

            log.error("❌ Échec demande réinitialisation pour: {}", request.getEmail(), e);
            throw e;
        }
    }

    /**
     * Confirmation et réinitialisation du mot de passe
     */
    @Transactional
    public ResponseDto confirmPasswordReset(PasswordResetConfirmRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            User user = userRepository.findByPasswordResetToken(request.getToken())
                    .orElseThrow(() -> new IllegalArgumentException("Token de réinitialisation invalide"));

            // Vérifier l'expiration
            if (user.getPasswordResetExpiresAt().isBefore(LocalDateTime.now())) {
                auditMicroserviceClient.logSecurityEvent(
                        "PASSWORD_RESET_EXPIRED_TOKEN",
                        user.getEmail(),
                        "MEDIUM",
                        "Tentative d'utilisation d'un token expiré",
                        httpRequest
                );

                throw new IllegalArgumentException("Le token de réinitialisation a expiré");
            }

            // Valider le nouveau mot de passe
            validatePasswordStrength(request.getNewPassword());

            // Vérifier qu'il ne réutilise pas le même mot de passe
            if (passwordEncoder.matches(request.getNewPassword(), user.getPasswd())) {
                throw new IllegalArgumentException("Le nouveau mot de passe doit être différent de l'ancien");
            }

            // Mettre à jour le mot de passe
            user.setPasswd(passwordEncoder.encode(request.getNewPassword()));
            user.resetPasswordResetAttempts();
            userRepository.save(user);

            // Envoyer confirmation par email
            sendPasswordChangeConfirmationEmail(user);

            // Audit
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "PASSWORD_RESET_COMPLETED",
                    user.getEmail(),
                    "Mot de passe réinitialisé avec succès",
                    httpRequest,
                    executionTime
            );

            auditMicroserviceClient.logSecurityEvent(
                    "PASSWORD_CHANGED_VIA_RESET",
                    user.getEmail(),
                    "HIGH",
                    "Changement de mot de passe via réinitialisation",
                    httpRequest
            );

            log.info("✅ Mot de passe réinitialisé pour: {}", user.getEmail());

            return ResponseDto.builder()
                    .success(true)
                    .message("Votre mot de passe a été réinitialisé avec succès")
                    .build();

        } catch (Exception e) {
            auditMicroserviceClient.logSecurityEvent(
                    "PASSWORD_RESET_FAILED",
                    "unknown",
                    "HIGH",
                    "Échec réinitialisation: " + e.getMessage(),
                    httpRequest
            );

            log.error("❌ Échec réinitialisation mot de passe", e);
            throw e;
        }
    }

    /**
     * Changement de mot de passe (utilisateur connecté)
     */
    @Transactional
    public ResponseDto changePassword(PasswordChangeRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        // Récupérer l'utilisateur connecté
        String currentUserEmail = SecurityContextHolder.getContext().getAuthentication().getName();

        try {
            User user = userRepository.findByEmail(currentUserEmail)
                    .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));

            // Vérifier si c'est un compte Google
            if (user.isGoogleUser() && (user.getPasswd() == null || user.getPasswd().isEmpty())) {
                throw new IllegalArgumentException("Les comptes Google ne peuvent pas avoir de mot de passe local");
            }

            // Vérifier le mot de passe actuel
            if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswd())) {
                auditMicroserviceClient.logSecurityEvent(
                        "PASSWORD_CHANGE_WRONG_CURRENT",
                        user.getEmail(),
                        "HIGH",
                        "Tentative changement mot de passe avec mauvais mot de passe actuel",
                        httpRequest
                );

                throw new IllegalArgumentException("Mot de passe actuel incorrect");
            }

            // Valider le nouveau mot de passe
            validatePasswordStrength(request.getNewPassword());

            // Vérifier qu'il ne réutilise pas le même
            if (passwordEncoder.matches(request.getNewPassword(), user.getPasswd())) {
                throw new IllegalArgumentException("Le nouveau mot de passe doit être différent de l'actuel");
            }

            // Changer le mot de passe
            user.setPasswd(passwordEncoder.encode(request.getNewPassword()));
            user.setLastPasswordChange(LocalDateTime.now());
            userRepository.save(user);

            // Envoyer confirmation
            sendPasswordChangeConfirmationEmail(user);

            // Audit
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "PASSWORD_CHANGED",
                    user.getEmail(),
                    "Mot de passe changé avec succès",
                    httpRequest,
                    executionTime
            );

            auditMicroserviceClient.logSecurityEvent(
                    "PASSWORD_CHANGED_BY_USER",
                    user.getEmail(),
                    "MEDIUM",
                    "Changement de mot de passe par l'utilisateur",
                    httpRequest
            );

            log.info("🔐 Mot de passe changé pour: {}", user.getEmail());

            return ResponseDto.builder()
                    .success(true)
                    .message("Votre mot de passe a été changé avec succès")
                    .build();

        } catch (Exception e) {
            auditMicroserviceClient.logAuditEvent(
                    "PASSWORD_CHANGE_FAILED",
                    currentUserEmail,
                    "Échec changement mot de passe: " + e.getMessage(),
                    httpRequest,
                    System.currentTimeMillis() - startTime
            );

            log.error("❌ Échec changement mot de passe pour: {}", currentUserEmail, e);
            throw e;
        }
    }

    /**
     * Nettoyage automatique des tokens expirés
     */
    @Scheduled(fixedRate = 3600000) // 1 heure
    @Transactional
    public void cleanupExpiredPasswordResetTokens() {
        try {
            LocalDateTime now = LocalDateTime.now();
            List<User> expiredUsers = userRepository.findAll().stream()
                    .filter(user -> user.getPasswordResetExpiresAt() != null &&
                            user.getPasswordResetExpiresAt().isBefore(now))
                    .toList();

            for (User user : expiredUsers) {
                user.setPasswordResetToken(null);
                user.setPasswordResetExpiresAt(null);
                userRepository.save(user);
            }

            if (!expiredUsers.isEmpty()) {
                log.info("🧹 {} tokens de réinitialisation expirés nettoyés", expiredUsers.size());
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage des tokens de réinitialisation", e);
        }
    }

    // Méthodes privées utilitaires
    private void validatePasswordStrength(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins 8 caractères");
        }

        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException(
                    "Le mot de passe doit contenir au moins : " +
                            "1 minuscule, 1 majuscule, 1 chiffre et 1 caractère spécial (@$!%*?&)"
            );
        }

        // Vérifier les mots de passe faibles courants
        if (isCommonPassword(password)) {
            throw new IllegalArgumentException("Ce mot de passe est trop courant. Choisissez un mot de passe plus unique.");
        }
    }

    private boolean isCommonPassword(String password) {
        // Liste des mots de passe courants à éviter
        String[] commonPasswords = {
                "password", "Password1", "123456789", "qwerty123", "admin123",
                "welcome123", "password123", "letmein123", "monkey123", "dragon123"
        };

        String lowerPassword = password.toLowerCase();
        for (String common : commonPasswords) {
            if (lowerPassword.contains(common.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private String generatePasswordResetToken() {
        return UUID.randomUUID().toString() + "-" + System.currentTimeMillis();
    }

    private void sendPasswordResetEmail(User user, String resetToken) {
        try {
            // Utiliser votre service de notification existant
            // Adapter selon votre implémentation du NotificationClient

            // Pour l'instant, log simulé
            log.info("📧 Envoi email réinitialisation à {} avec token: {}", user.getEmail(), resetToken);

            // TODO: Implémenter l'envoi réel via NotificationClient
            // notificationClient.sendPasswordResetEmail(user.getEmail(), user.getName(), resetToken);

        } catch (Exception e) {
            log.error("❌ Erreur envoi email réinitialisation pour: {}", user.getEmail(), e);
        }
    }

    private void sendPasswordChangeConfirmationEmail(User user) {
        try {
            log.info("📧 Envoi confirmation changement mot de passe à: {}", user.getEmail());

            // TODO: Implémenter l'envoi réel via NotificationClient
            // notificationClient.sendPasswordChangeConfirmation(user.getEmail(), user.getName());

        } catch (Exception e) {
            log.error("❌ Erreur envoi confirmation changement mot de passe pour: {}", user.getEmail(), e);
        }
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }

    /**
     * Vérifier la force d'un mot de passe (utilitaire public)
     */
    public PasswordStrengthInfo checkPasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return PasswordStrengthInfo.builder()
                    .score(0)
                    .strength("TRÈS FAIBLE")
                    .suggestions(List.of("Le mot de passe ne peut pas être vide"))
                    .build();
        }

        int score = 0;
        List<String> suggestions = new java.util.ArrayList<>();

        // Longueur
        if (password.length() >= 8) score += 1;
        else suggestions.add("Utilisez au moins 8 caractères");

        if (password.length() >= 12) score += 1;

        // Complexité
        if (password.matches(".*[a-z].*")) score += 1;
        else suggestions.add("Ajoutez des lettres minuscules");

        if (password.matches(".*[A-Z].*")) score += 1;
        else suggestions.add("Ajoutez des lettres majuscules");

        if (password.matches(".*\\d.*")) score += 1;
        else suggestions.add("Ajoutez des chiffres");

        if (password.matches(".*[@$!%*?&].*")) score += 1;
        else suggestions.add("Ajoutez des caractères spéciaux (@$!%*?&)");

        // Vérifier les patterns courants
        if (isCommonPassword(password)) {
            score -= 2;
            suggestions.add("Évitez les mots de passe courants");
        }

        // Déterminer la force
        String strength;
        if (score <= 2) strength = "FAIBLE";
        else if (score <= 4) strength = "MOYEN";
        else if (score <= 6) strength = "FORT";
        else strength = "TRÈS FORT";

        return PasswordStrengthInfo.builder()
                .score(Math.max(0, score))
                .strength(strength)
                .suggestions(suggestions)
                .build();
    }
}